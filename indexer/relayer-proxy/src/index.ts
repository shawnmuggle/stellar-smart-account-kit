/**
 * Smart Account Relayer Proxy - Cloudflare Worker
 *
 * This worker provides a proxy for OpenZeppelin Relayer Channels service,
 * with a self-sponsored fallback for mainnet when OZ channels are underfunded.
 *
 * Features:
 * - Primary: Uses OZ Relayer Channels SDK for gas sponsoring
 * - Fallback: Self-sponsored mode using your own funded G-address
 * - Automatic API key generation per IP address (persisted indefinitely)
 * - Rate limiting via Relayer's built-in fair use policy
 * - Separate deployments for testnet and mainnet
 *
 * On mainnet, if OZ Channels fail with TxInsufficientBalance, we fall back
 * to self-sponsored mode using SPONSOR_SECRET_KEY.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  ChannelsClient,
  PluginExecutionError,
  PluginTransportError,
} from "@openzeppelin/relayer-plugin-channels";
import {
  Keypair,
  TransactionBuilder,
  Operation,
  xdr,
  Networks,
  Transaction,
  rpc,
} from "@stellar/stellar-sdk";

interface StoredApiKey {
  apiKey: string;
  createdAt: number;
}

// Hono app with typed environment bindings
const app = new Hono<{ Bindings: Env }>();

// Enable CORS
app.use("*", cors());

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get client IP from request
 */
function getClientIP(request: Request): string {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    request.headers.get("X-Real-IP") ||
    "unknown"
  );
}

/**
 * Generate a unique key for KV storage
 */
function getKVKey(ip: string): string {
  return `api-key:${ip}`;
}

/**
 * Get or generate an API key for the given IP.
 * Keys are stored indefinitely - one key per IP address.
 * The Relayer's usage limits reset every 24 hours on their side.
 */
async function getOrCreateApiKey(
  env: Env,
  ip: string
): Promise<{ apiKey: string; isNew: boolean } | null> {
  const kvKey = getKVKey(ip);

  // Check if we already have an API key for this IP
  const cached = (await env.API_KEYS.get(kvKey, "json")) as StoredApiKey | null;
  if (cached) {
    return { apiKey: cached.apiKey, isNew: false };
  }

  // No existing key - generate a new one from Relayer's /gen endpoint
  const newApiKey = await generateApiKey(env);
  if (!newApiKey) {
    return null;
  }

  // Store the new API key (no expiration - persists indefinitely)
  const storedKey: StoredApiKey = {
    apiKey: newApiKey,
    createdAt: Date.now(),
  };

  // Store without expiration TTL - key persists until manually deleted
  await env.API_KEYS.put(kvKey, JSON.stringify(storedKey));

  return { apiKey: newApiKey, isNew: true };
}

/**
 * Generate a new API key from the Relayer service.
 * Calls the /gen endpoint which requires no authentication.
 * @see https://docs.openzeppelin.com/relayer/1.3.x/guides/stellar-channels-guide
 */
async function generateApiKey(env: Env): Promise<string | null> {
  try {
    // The /gen endpoint generates a new API key - no auth required (GET request)
    const response = await fetch(`${env.RELAYER_BASE_URL}/gen`, {
      method: "GET",
    });

    const text = await response.text();

    if (response.ok) {
      try {
        const data = JSON.parse(text) as Record<string, unknown>;
        // Try various possible key names
        const apiKey = data.apiKey || data.api_key || data.key || data.token;
        if (typeof apiKey === "string") {
          return apiKey;
        }
        console.error("API key not found in response:", data);
        return null;
      } catch {
        // Response might be plain text API key
        if (text && text.length > 10 && text.length < 200) {
          return text.trim();
        }
        console.error("Could not parse API key response:", text);
        return null;
      }
    }

    console.error("Failed to generate API key:", response.status, text);
    return null;
  } catch (error) {
    console.error("Error generating API key:", error);
    return null;
  }
}

/**
 * Create a ChannelsClient for the configured network
 */
function createClient(env: Env, apiKey: string): ChannelsClient {
  return new ChannelsClient({
    baseUrl: env.RELAYER_BASE_URL,
    apiKey,
  });
}

/**
 * Extract account address from "Account not found" error message
 */
function extractMissingAccount(errorMessage: string): string | null {
  // Pattern: "Account not found: GXXXX..."
  const match = errorMessage.match(/Account not found:\s*(G[A-Z0-9]{55})/);
  return match ? match[1] : null;
}

/**
 * Fund an account via Friendbot (testnet only)
 */
async function fundWithFriendbot(account: string): Promise<boolean> {
  try {
    const response = await fetch(
      `https://friendbot.stellar.org?addr=${encodeURIComponent(account)}`
    );
    return response.ok;
  } catch (error) {
    console.error("Friendbot funding failed:", error);
    return false;
  }
}

/**
 * Get network passphrase based on environment
 */
function getNetworkPassphrase(network: string): string {
  return network === "mainnet"
    ? Networks.PUBLIC
    : Networks.TESTNET;
}

/**
 * Get RPC URL based on environment
 */
function getRpcUrl(network: string): string {
  return network === "mainnet"
    ? "https://soroban-rpc.mainnet.stellar.gateway.fm"
    : "https://soroban-testnet.stellar.org";
}

/**
 * Self-sponsored transaction submission.
 * Builds and submits a transaction using your own funded G-address as the fee payer.
 *
 * This is used as a fallback when OZ Channels fail (e.g., underfunded on mainnet).
 */
async function submitSelfSponsored(
  env: Env,
  func: string,
  auth: string[]
): Promise<{ hash: string; status: string }> {
  if (!env.SPONSOR_SECRET_KEY) {
    throw new Error("Self-sponsored mode not configured: SPONSOR_SECRET_KEY missing");
  }

  const networkPassphrase = getNetworkPassphrase(env.NETWORK);
  const rpcUrl = getRpcUrl(env.NETWORK);
  const server = new rpc.Server(rpcUrl);

  // Parse the sponsor keypair
  const sponsorKeypair = Keypair.fromSecret(env.SPONSOR_SECRET_KEY);
  const sponsorPublicKey = sponsorKeypair.publicKey();

  // Get the sponsor account
  const sponsorAccount = await server.getAccount(sponsorPublicKey);

  // Parse the host function from base64 XDR
  const hostFunction = xdr.HostFunction.fromXDR(func, "base64");

  // Parse auth entries from base64 XDR
  const authEntries = auth.map((a) => xdr.SorobanAuthorizationEntry.fromXDR(a, "base64"));

  // Build the transaction with invokeHostFunction operation
  const transaction = new TransactionBuilder(sponsorAccount, {
    fee: "1000000", // 0.1 XLM max fee (will be adjusted by simulation)
    networkPassphrase,
  })
    .addOperation(
      Operation.invokeHostFunction({
        func: hostFunction,
        auth: authEntries,
      })
    )
    .setTimeout(60)
    .build();

  // Simulate the transaction to get resource requirements
  const simResult = await server.simulateTransaction(transaction);

  if (rpc.Api.isSimulationError(simResult)) {
    throw new Error(`Simulation failed: ${simResult.error}`);
  }

  if (!rpc.Api.isSimulationSuccess(simResult)) {
    throw new Error("Simulation did not succeed");
  }

  // Assemble the transaction with simulation results
  const preparedTx = rpc.assembleTransaction(
    transaction,
    simResult
  ).build();

  // Sign with sponsor keypair
  preparedTx.sign(sponsorKeypair);

  // Submit the transaction
  const sendResult = await server.sendTransaction(preparedTx);

  if (sendResult.status === "ERROR") {
    throw new Error(`Transaction submission failed: ${sendResult.errorResult?.toXDR("base64") || "unknown error"}`);
  }

  // Poll for result
  const hash = sendResult.hash;
  let getResult = await server.getTransaction(hash);
  const maxWaitMs = 30000;
  const startTime = Date.now();

  while (getResult.status === "NOT_FOUND" && Date.now() - startTime < maxWaitMs) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    getResult = await server.getTransaction(hash);
  }

  if (getResult.status === "SUCCESS") {
    return { hash, status: "SUCCESS" };
  } else if (getResult.status === "FAILED") {
    throw new Error(`Transaction failed on-chain: ${hash}`);
  } else {
    // Still NOT_FOUND after waiting
    return { hash, status: "PENDING" };
  }
}

/**
 * Self-sponsored XDR submission (fee-bump).
 * Wraps a signed transaction in a fee-bump transaction using your sponsor account.
 */
async function submitSelfSponsoredXdr(
  env: Env,
  txXdr: string
): Promise<{ hash: string; status: string }> {
  if (!env.SPONSOR_SECRET_KEY) {
    throw new Error("Self-sponsored mode not configured: SPONSOR_SECRET_KEY missing");
  }

  const networkPassphrase = getNetworkPassphrase(env.NETWORK);
  const rpcUrl = getRpcUrl(env.NETWORK);
  const server = new rpc.Server(rpcUrl);

  // Parse the sponsor keypair
  const sponsorKeypair = Keypair.fromSecret(env.SPONSOR_SECRET_KEY);

  // Parse the inner transaction
  const innerTx = TransactionBuilder.fromXDR(txXdr, networkPassphrase) as Transaction;

  // Create a fee-bump transaction
  const feeBumpTx = TransactionBuilder.buildFeeBumpTransaction(
    sponsorKeypair,
    "1000000", // 0.1 XLM max fee
    innerTx,
    networkPassphrase
  );

  // Sign the fee-bump with sponsor
  feeBumpTx.sign(sponsorKeypair);

  // Submit the fee-bump transaction
  const sendResult = await server.sendTransaction(feeBumpTx);

  if (sendResult.status === "ERROR") {
    throw new Error(`Transaction submission failed: ${sendResult.errorResult?.toXDR("base64") || "unknown error"}`);
  }

  // Poll for result
  const hash = sendResult.hash;
  let getResult = await server.getTransaction(hash);
  const maxWaitMs = 30000;
  const startTime = Date.now();

  while (getResult.status === "NOT_FOUND" && Date.now() - startTime < maxWaitMs) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    getResult = await server.getTransaction(hash);
  }

  if (getResult.status === "SUCCESS") {
    return { hash, status: "SUCCESS" };
  } else if (getResult.status === "FAILED") {
    throw new Error(`Transaction failed on-chain: ${hash}`);
  } else {
    return { hash, status: "PENDING" };
  }
}

// ============================================================================
// API Endpoints
// ============================================================================

// Health check
app.get("/", (c) => {
  const hasSponsor = !!c.env.SPONSOR_SECRET_KEY;
  return c.json({
    status: "ok",
    service: "smart-account-relayer-proxy",
    network: c.env.NETWORK,
    selfSponsorEnabled: hasSponsor,
  });
});

/**
 * Submit a transaction via Relayer
 * POST /
 *
 * Two modes:
 * 1. { func: string, auth: string[] } - Builds tx with sponsor account
 * 2. { xdr: string } - Fee-bumps a signed transaction
 *
 * Use func+auth for Address credentials (transfers, wallet operations).
 * Use xdr for source_account auth (deployment) - tx must be signed.
 *
 * Network behavior:
 * - Mainnet: Uses self-sponsored mode (SPONSOR_SECRET_KEY required)
 * - Testnet: Uses OZ Channels with Friendbot retry for missing accounts
 */
app.post("/", async (c) => {
  const ip = getClientIP(c.req.raw);
  const isMainnet = c.env.NETWORK === "mainnet";
  const hasSponsor = !!c.env.SPONSOR_SECRET_KEY;

  try {
    const body = await c.req.json<{
      func?: string;
      auth?: string[];
      xdr?: string;
    }>();

    // Validate: must have either xdr OR (func AND auth)
    const hasXdr = !!body.xdr;
    const hasFuncAuth = !!body.func && !!body.auth;

    if (!hasXdr && !hasFuncAuth) {
      return c.json(
        { success: false, error: "Request must include 'xdr' OR ('func' and 'auth')" },
        400
      );
    }

    if (hasXdr && hasFuncAuth) {
      return c.json(
        { success: false, error: "Request must include 'xdr' OR ('func' and 'auth'), not both" },
        400
      );
    }

    // ========================================================================
    // MAINNET: Use self-sponsored mode by default
    // ========================================================================
    if (isMainnet) {
      if (!hasSponsor) {
        return c.json(
          {
            success: false,
            error: "Mainnet requires SPONSOR_SECRET_KEY to be configured.",
          },
          500
        );
      }

      console.log("Mainnet: Using self-sponsored mode...");

      try {
        if (hasXdr) {
          const result = await submitSelfSponsoredXdr(c.env, body.xdr!);
          return c.json({
            success: true,
            data: {
              hash: result.hash,
              status: result.status,
              mode: "self-sponsored",
            },
          });
        } else {
          const result = await submitSelfSponsored(c.env, body.func!, body.auth!);
          return c.json({
            success: true,
            data: {
              hash: result.hash,
              status: result.status,
              mode: "self-sponsored",
            },
          });
        }
      } catch (selfSponsorError) {
        console.error("Self-sponsored submission failed:", selfSponsorError);
        return c.json(
          {
            success: false,
            error: selfSponsorError instanceof Error ? selfSponsorError.message : "Self-sponsored submission failed",
            mode: "self-sponsored",
          },
          500
        );
      }
    }

    // ========================================================================
    // TESTNET: Use OZ Channels with Friendbot retry
    // ========================================================================
    const apiKeyResult = await getOrCreateApiKey(c.env, ip);

    if (!apiKeyResult) {
      return c.json(
        {
          success: false,
          error: "Could not obtain API key from OZ Channels.",
        },
        500
      );
    }

    const client = createClient(c.env, apiKeyResult.apiKey);

    // On testnet, retry for up to 5 minutes to handle channel accounts needing funding
    const TESTNET_RETRY_DURATION_MS = 5 * 60 * 1000; // 5 minutes
    const deadline = Date.now() + TESTNET_RETRY_DURATION_MS;
    const fundedAccounts = new Set<string>(); // Track accounts we've already funded

    // Submit with retry logic for missing accounts
    while (true) {
      try {
        if (hasXdr) {
          // Fee-bump a signed transaction
          const result = await client.submitTransaction({ xdr: body.xdr! });
          return c.json({
            success: true,
            data: {
              transactionId: result.transactionId,
              hash: result.hash,
              status: result.status,
              mode: "oz-channels",
            },
          });
        } else {
          // Build tx with channel accounts
          const result = await client.submitSorobanTransaction({
            func: body.func!,
            auth: body.auth!,
          });
          return c.json({
            success: true,
            data: {
              transactionId: result.transactionId,
              hash: result.hash,
              status: result.status,
              mode: "oz-channels",
            },
          });
        }
      } catch (submitError) {
        const errorMessage = submitError instanceof Error ? submitError.message : String(submitError);

        // Check if this is a "missing account" error (testnet reset scenario)
        const missingAccount = extractMissingAccount(errorMessage);
        const timeRemaining = deadline - Date.now();

        if (missingAccount && timeRemaining > 0) {
          // Only fund each account once per request
          if (!fundedAccounts.has(missingAccount)) {
            console.log(`Account ${missingAccount} not found. Funding via friendbot (${Math.round(timeRemaining / 1000)}s remaining)...`);

            const funded = await fundWithFriendbot(missingAccount);
            if (funded) {
              console.log(`Successfully funded ${missingAccount}. Retrying submission...`);
              fundedAccounts.add(missingAccount);
            } else {
              console.error(`Failed to fund ${missingAccount}`);
            }
          } else {
            console.log(`Account ${missingAccount} already funded, retrying...`);
          }

          continue; // Retry immediately
        }

        // Not a recoverable error or deadline exceeded - throw to outer handler
        throw submitError;
      }
    }
  } catch (error) {
    console.error("Relayer submission error:", error);

    if (error instanceof PluginExecutionError) {
      return c.json(
        {
          success: false,
          error: error.message,
          data: {
            code: error.errorDetails?.code,
            details: error.errorDetails?.details,
          },
        },
        400
      );
    }

    if (error instanceof PluginTransportError) {
      const status = error.statusCode || 500;
      return c.json(
        {
          success: false,
          error: error.message,
        },
        status as 400 | 401 | 403 | 404 | 500 | 502 | 503
      );
    }

    return c.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Relayer request failed",
      },
      500
    );
  }
});

/**
 * Get fee usage for the current IP
 * GET /fee-usage
 */
app.get("/fee-usage", async (c) => {
  const ip = getClientIP(c.req.raw);
  const kvKey = getKVKey(ip);

  // Check if we have an API key for this IP
  const cached = (await c.env.API_KEYS.get(kvKey, "json")) as StoredApiKey | null;

  if (!cached) {
    return c.json({
      success: true,
      data: {
        hasKey: false,
        message: "No API key assigned yet. Submit a transaction to get one.",
      },
    });
  }

  // Fee usage query requires admin access which we don't have for the managed service
  // Just return key info
  return c.json({
    success: true,
    data: {
      hasKey: true,
      keyCreatedAt: cached.createdAt,
      network: c.env.NETWORK,
      message: "Fee usage details not available for managed service.",
    },
  });
});

/**
 * Get proxy status and client info
 * GET /status
 */
app.get("/status", async (c) => {
  const ip = getClientIP(c.req.raw);
  const kvKey = getKVKey(ip);

  const apiKey = (await c.env.API_KEYS.get(kvKey, "json")) as StoredApiKey | null;
  const hasSponsor = !!c.env.SPONSOR_SECRET_KEY;

  return c.json({
    success: true,
    data: {
      clientIP: ip,
      network: c.env.NETWORK,
      hasKey: !!apiKey,
      keyCreatedAt: apiKey?.createdAt,
      selfSponsorEnabled: hasSponsor,
    },
  });
});

// ============================================================================
// Worker Export
// ============================================================================

export default {
  fetch: app.fetch,
};
