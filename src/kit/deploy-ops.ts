import {
  hash,
  xdr,
  nativeToScVal,
  Address,
  TransactionBuilder,
  Operation,
  Transaction,
  StrKey,
} from "@stellar/stellar-sdk";
import type { contract, Keypair } from "@stellar/stellar-sdk";
import { rpc } from "@stellar/stellar-sdk";
import type { SubmissionOptions, TransactionResult } from "../types";
import type { RelayerClient } from "../relayer";
import type { StorageAdapter } from "../types";
import { buildKeyData } from "../utils";
import type { Signer as ContractSigner } from "smart-account-kit-bindings";
import { Client as SmartAccountClient } from "smart-account-kit-bindings";
import { getSubmissionMethod } from "./tx-ops";

export async function submitDeploymentTx<T>(
  deps: {
    storage: StorageAdapter;
    rpc: rpc.Server;
    relayer: RelayerClient | null;
  },
  tx: contract.AssembledTransaction<T>,
  credentialId: string,
  options?: SubmissionOptions
): Promise<TransactionResult> {
  try {
    let hashValue: string;
    let ledger: number | undefined;

    const method = getSubmissionMethod(deps.relayer, options);

    if (method === "relayer" && tx.signed && deps.relayer) {
      const relayerResult = await deps.relayer.sendXdr(tx.signed);

      if (!relayerResult.success) {
        throw new Error(relayerResult.error ?? "Relayer submission failed");
      }

      hashValue = relayerResult.hash ?? "";

      const txResult = await deps.rpc.pollTransaction(hashValue, { attempts: 10 });
      if (txResult.status === "SUCCESS") {
        ledger = txResult.ledger;
      } else if (txResult.status === "FAILED") {
        throw new Error("Transaction failed on-chain");
      }
    } else {
      const sentTx = await tx.send();
      const txResponse = sentTx.getTransactionResponse;
      hashValue = sentTx.sendTransactionResponse?.hash ?? "";
      ledger = txResponse?.status === "SUCCESS" ? txResponse.ledger : undefined;
    }

    await deps.storage.delete(credentialId);
    return {
      success: true,
      hash: hashValue,
      ledger,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : "Transaction failed";
    await deps.storage.update(credentialId, {
      deploymentStatus: "failed",
      deploymentError: error,
    });
    return {
      success: false,
      hash: "",
      error,
    };
  }
}

export async function buildDeployTransaction(
  deps: {
    accountWasmHash: string;
    webauthnVerifierAddress: string;
    networkPassphrase: string;
    rpcUrl: string;
    deployerKeypair: Keypair;
    timeoutInSeconds: number;
  },
  credentialId: Buffer,
  publicKey: Uint8Array
): Promise<contract.AssembledTransaction<null>> {
  const keyData = buildKeyData(publicKey, credentialId);
  const signer: ContractSigner = {
    tag: "External",
    values: [
      deps.webauthnVerifierAddress,
      keyData,
    ],
  };

  return SmartAccountClient.deploy(
    {
      signers: [signer],
      policies: new Map(),
    },
    {
      networkPassphrase: deps.networkPassphrase,
      rpcUrl: deps.rpcUrl,
      wasmHash: deps.accountWasmHash,
      publicKey: deps.deployerKeypair.publicKey(),
      salt: hash(credentialId),
      timeoutInSeconds: deps.timeoutInSeconds,
    }
  );
}

// ============================================================================
// Factory-based Deployment (for gas-sponsored deployments)
// ============================================================================

/**
 * Derive contract address from factory contract and salt.
 * The address is derived from (factory_address, hash(credentialId)).
 */
export function deriveFactoryContractAddress(
  factoryAddress: string,
  credentialId: Buffer,
  networkPassphrase: string
): string {
  const salt = hash(credentialId);
  const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
    new xdr.HashIdPreimageContractId({
      networkId: hash(Buffer.from(networkPassphrase)),
      contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
        new xdr.ContractIdPreimageFromAddress({
          address: Address.fromString(factoryAddress).toScAddress(),
          salt,
        })
      ),
    })
  );

  return StrKey.encodeContract(hash(preimage.toXDR()));
}

/**
 * Build a factory deployment transaction.
 *
 * Unlike direct deployment (which uses source_account auth), factory deployment
 * is a permissionless contract invocation that can be fully sponsored via Relayer.
 *
 * The factory's deploy function signature:
 * deploy(wasm_hash: BytesN<32>, salt: BytesN<32>, constructor_args: Vec<Val>) -> Address
 */
export async function buildFactoryDeployTransaction(
  deps: {
    factoryContractAddress: string;
    accountWasmHash: string;
    webauthnVerifierAddress: string;
    networkPassphrase: string;
    rpc: rpc.Server;
    deployerKeypair: Keypair;
    timeoutInSeconds: number;
  },
  credentialId: Buffer,
  publicKey: Uint8Array
): Promise<{
  transaction: Transaction;
  contractId: string;
  hostFunc: xdr.HostFunction;
}> {
  const salt = hash(credentialId);
  const keyData = buildKeyData(publicKey, credentialId);

  // Build External signer: External(verifier_address, key_data)
  const signerEnum = xdr.ScVal.scvVec([
    nativeToScVal("External", { type: "symbol" }),
    Address.fromString(deps.webauthnVerifierAddress).toScVal(),
    nativeToScVal(keyData, { type: "bytes" }),
  ]);

  // Constructor args: (signers: Vec<Signer>, policies: Map<Address, Val>)
  const constructorArgs = xdr.ScVal.scvVec([
    xdr.ScVal.scvVec([signerEnum]), // one signer
    xdr.ScVal.scvMap([]), // empty policies
  ]);

  // Build the factory.deploy() invocation
  const factoryAddress = Address.fromString(deps.factoryContractAddress);

  const hostFunc = xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: factoryAddress.toScAddress(),
      functionName: "deploy",
      args: [
        // wasm_hash: BytesN<32>
        nativeToScVal(Buffer.from(deps.accountWasmHash, "hex"), { type: "bytes" }),
        // salt: BytesN<32>
        nativeToScVal(salt, { type: "bytes" }),
        // constructor_args: Vec<Val>
        constructorArgs,
      ],
    })
  );

  // Get deployer account for transaction building
  const deployerAccount = await deps.rpc.getAccount(deps.deployerKeypair.publicKey());

  // Build initial transaction for simulation
  const txBuilder = new TransactionBuilder(deployerAccount, {
    fee: "10000000", // Will be updated after simulation
    networkPassphrase: deps.networkPassphrase,
  });

  txBuilder.addOperation(
    Operation.invokeHostFunction({
      func: hostFunc,
      auth: [],
    })
  );

  txBuilder.setTimeout(deps.timeoutInSeconds);
  const builtTx = txBuilder.build();

  // Simulate to get resource costs
  const simResult = await deps.rpc.simulateTransaction(builtTx);

  if ("error" in simResult && simResult.error) {
    throw new Error(`Factory deploy simulation failed: ${simResult.error}`);
  }

  // Calculate the contract address that will be deployed
  const contractId = deriveFactoryContractAddress(
    deps.factoryContractAddress,
    credentialId,
    deps.networkPassphrase
  );

  // Assemble the transaction with proper resources
  const assembledTx = rpc.assembleTransaction(builtTx, simResult);
  const preparedTx = assembledTx.build() as Transaction;

  return {
    transaction: preparedTx,
    contractId,
    hostFunc,
  };
}

/**
 * Submit a factory deployment transaction.
 *
 * This handles the full flow for factory-based deployment:
 * 1. If using Relayer, sends func + empty auth (fully sponsored, no signing needed)
 * 2. If using RPC, signs with deployer and submits
 */
export async function submitFactoryDeploymentTx(
  deps: {
    storage: StorageAdapter;
    rpc: rpc.Server;
    relayer: RelayerClient | null;
    deployerKeypair: Keypair;
  },
  transaction: Transaction,
  hostFunc: xdr.HostFunction,
  credentialId: string,
  options?: SubmissionOptions
): Promise<TransactionResult> {
  try {
    const method = getSubmissionMethod(deps.relayer, options);

    let hashValue: string;
    let ledger: number | undefined;

    if (method === "relayer" && deps.relayer) {
      // For Relayer: send func + empty auth (no signatures needed for permissionless factory)
      const funcXdr = hostFunc.toXDR("base64");

      const relayerResult = await deps.relayer.send(funcXdr, []);

      if (!relayerResult.success) {
        throw new Error(relayerResult.error ?? "Relayer submission failed");
      }

      hashValue = relayerResult.hash ?? "";

      // Poll for confirmation
      const txResult = await deps.rpc.pollTransaction(hashValue, { attempts: 15 });
      ledger = txResult.status === "SUCCESS" ? txResult.ledger : undefined;

      if (txResult.status === "FAILED") {
        throw new Error("Transaction failed on-chain");
      }
    } else {
      // For RPC: sign with deployer and submit directly
      transaction.sign(deps.deployerKeypair);

      const sendResult = await deps.rpc.sendTransaction(transaction);

      if (sendResult.status === "ERROR") {
        throw new Error(sendResult.errorResult?.result().switch().name ?? "Send failed");
      }

      hashValue = sendResult.hash;

      // Poll for confirmation
      const txResult = await deps.rpc.pollTransaction(hashValue, { attempts: 15 });
      ledger = txResult.status === "SUCCESS" ? txResult.ledger : undefined;

      if (txResult.status === "FAILED") {
        throw new Error("Transaction failed on-chain");
      }
    }

    // Success - clean up pending credential from storage
    await deps.storage.delete(credentialId);

    return {
      success: true,
      hash: hashValue,
      ledger,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : "Factory deployment failed";
    await deps.storage.update(credentialId, {
      deploymentStatus: "failed",
      deploymentError: error,
    });
    return {
      success: false,
      hash: "",
      error,
    };
  }
}
