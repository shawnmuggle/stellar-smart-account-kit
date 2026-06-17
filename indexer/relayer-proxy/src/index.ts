/**
 * Smart Account Relayer Proxy - Cloudflare Worker
 *
 * This worker provides a proxy for transaction sponsoring on Stellar.
 *
 * Features:
 * - OZ Channels mode: Uses OZ Relayer Channels SDK for gas sponsoring
 * - Self-sponsored mode: Uses your own funded G-address as fee payer
 * - Mode controlled by SPONSOR_MODE env var ("1"/"true" = self-sponsored, default = OZ Channels)
 * - Automatic API key generation per IP address (OZ Channels mode)
 * - Separate deployments for testnet and mainnet
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

// Augment the wrangler-generated global Env with the optional Rozo payin-notify
// config. These are secrets set via `wrangler secret put`, so they don't appear
// in wrangler.toml [vars] and aren't picked up by `wrangler types`. `declare
// global` merges into the global `interface Env` (from worker-configuration.d.ts)
// instead of shadowing it, so API_KEYS/NETWORK/SPONSOR_SECRET_KEY stay intact.
declare global {
  interface Env {
    /** Rozo backend base URL, e.g. https://intentapiv4.rozo.ai/functions/v1 */
    PAYIN_NOTIFY_URL?: string;
    /** Shared secret sent as X-Relayer-Token so the backend can trust this caller */
    WALLETAPP_PAYIN_NOTIFY_TOKEN?: string;
  }
}

// Hono app with typed environment bindings
const app = new Hono<{ Bindings: Env }>();

// Enable CORS
app.use("*", cors());

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Check if self-sponsored mode is enabled via SPONSOR_MODE env var
 */
function isSelfSponsored(env: Env): boolean {
  const mode = (env.SPONSOR_MODE || "").trim().toLowerCase();
  return mode === "1" || mode === "true";
}

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

  // sendTransaction status ∈ PENDING | DUPLICATE | TRY_AGAIN_LATER | ERROR.
  // Only ERROR (RPC outright rejected the submit) throws — same as before.
  // We DELIBERATELY do NOT throw on TRY_AGAIN_LATER: the current frontend hasn't
  // been upgraded to handle a new error shape, and throwing would surface a
  // brand-new failure to existing App users. Instead we log it (visible in
  // Workers Logs) so we can SEE how often the RPC soft-rejects a submit on weak
  // networks, while preserving the existing return-hash-PENDING behavior. The
  // backend backstops (finalizeSubmission poll + reconciler + cron) handle the
  // case where such a tx never actually lands.
  if (sendResult.status === "ERROR") {
    throw new Error(`Transaction submission failed: ${sendResult.errorResult?.toXDR("base64") || "unknown error"}`);
  }
  if (sendResult.status === "TRY_AGAIN_LATER") {
    console.warn(`[Submit] sendTransaction TRY_AGAIN_LATER (not broadcast) tx=${maskHash(sendResult.hash || "")} — returning PENDING anyway for FE compat`);
  } else {
    console.log(`[Submit] sendTransaction ${sendResult.status} tx=${maskHash(sendResult.hash || "")}`);
  }

  // A+D weak-network fix: submission succeeded → return the hash IMMEDIATELY
  // with status PENDING. We DO NOT block the request polling getTransaction for
  // up to 30s anymore — that required the (possibly weak-network) client
  // connection to survive ~35s, and a drop in that window left the tx maybe
  // on-chain with the hash never reaching the client (order stuck unpaid,
  // invisible). "Wait for on-chain finality" now runs in the worker's
  // executionCtx.waitUntil (finalizeSubmission) + the backend's /payin recheck,
  // getEvents cron, Mercury webhook, and the relayer_submissions reconciler.
  // sendResult.status === "ERROR" still throws above (RPC rejected the submit =
  // real failure the client must hear about). See
  // internaldocs/20260616-relayer-submit-decouple-weaknet.md (backend repo).
  return { hash: sendResult.hash, status: "PENDING" };
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

  // Only ERROR throws (same as before). TRY_AGAIN_LATER is logged, not thrown —
  // see submitSelfSponsored above: don't surface a new error to the un-upgraded
  // frontend; keep returning hash+PENDING and let the backend backstops catch
  // a tx that never lands.
  if (sendResult.status === "ERROR") {
    throw new Error(`Transaction submission failed: ${sendResult.errorResult?.toXDR("base64") || "unknown error"}`);
  }
  if (sendResult.status === "TRY_AGAIN_LATER") {
    console.warn(`[SubmitXdr] sendTransaction TRY_AGAIN_LATER (not broadcast) tx=${maskHash(sendResult.hash || "")} — returning PENDING anyway for FE compat`);
  } else {
    console.log(`[SubmitXdr] sendTransaction ${sendResult.status} tx=${maskHash(sendResult.hash || "")}`);
  }

  // A+D weak-network fix (see submitSelfSponsored above for the full rationale):
  // return the hash immediately with PENDING; finality is resolved off the
  // request path by finalizeSubmission (waitUntil) + backend backstops.
  return { hash: sendResult.hash, status: "PENDING" };
}

/**
 * Fire-and-forget notify the Rozo backend's /payin endpoint that a Stellar
 * contract payin just landed on-chain. This is the whole point of the
 * relayer-notify fast-path: the worker is the earliest place that knows the tx
 * hash + SUCCESS, ~4.5s before the hash relays back to the frontend.
 *
 * Strictly best-effort and additive:
 * - No-op unless PAYIN_NOTIFY_URL is configured AND paymentId is present.
 * - Errors are swallowed; the frontend /payin callback + backend cron/mercury
 *   remain the source of truth, so a dropped notify never loses a payment.
 * - Only the HTTP status is logged — NEVER the body or the auth token.
 *
 * Call via c.executionCtx.waitUntil(...) so the response returns immediately.
 */
async function notifyPayinBackend(
  env: Env,
  paymentId: string,
  txHash: string,
  fromAddress?: string
): Promise<void> {
  if (!env.PAYIN_NOTIFY_URL) return; // not configured → no-op
  // Basic UUID shape guard so a malformed paymentId never reaches the backend.
  if (!/^[0-9a-fA-F-]{32,40}$/.test(paymentId)) {
    console.log("[PayinNotify] skipped: paymentId not UUID-shaped");
    return;
  }

  const base = env.PAYIN_NOTIFY_URL.replace(/\/+$/, "");
  const url = `${base}/payment-api/payments/${encodeURIComponent(paymentId)}/payin`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (env.WALLETAPP_PAYIN_NOTIFY_TOKEN) {
    // Distinguishes a trusted relayer callback from a public /payin call so the
    // backend can relax/tighten accordingly. Token is a secret (wrangler secret).
    headers["X-Relayer-Token"] = env.WALLETAPP_PAYIN_NOTIFY_TOKEN;
  }
  const body = JSON.stringify({
    txHash,
    ...(fromAddress ? { fromAddress } : {}),
  });

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(url, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    // Log status only — never the body (may contain order detail) or token.
    console.log(`[PayinNotify] paymentId=${paymentId} HTTP ${res.status}`);
  } catch (err) {
    console.error(
      `[PayinNotify] paymentId=${paymentId} failed:`,
      err instanceof Error ? err.message : "unknown error"
    );
  }
}

/**
 * Mask a tx hash for logging: first 6 + last 4 only. The hash is public chain
 * data, but we keep logs terse and consistent with the backend's masking.
 */
function maskHash(h: string): string {
  return h.length > 12 ? `${h.slice(0, 6)}…${h.slice(-4)}` : "<hash>";
}

/**
 * Fire-and-forget upsert into the backend's relayer_submissions table (method
 * D of the A+D weak-network fix). This is the SERVER-SIDE record that makes a
 * "submitted but the client may not have received the hash" tx visible to ops
 * even when this isolate dies. Best-effort, additive, never throws.
 *
 * Posts to {PAYIN_NOTIFY_URL}/payment-api/relayer-submissions with the shared
 * X-Relayer-Token. No-op unless PAYIN_NOTIFY_URL is configured. Logs HTTP
 * status + masked hash + outcome only — NEVER the token, full body, or raw
 * error text (network/RPC error messages can be noisy; we log a coarse tag).
 *
 * Returns true iff the row was durably accepted (HTTP 2xx). The caller uses
 * this for the stage-1 retry (codex P1): a failed pending_unknown write means
 * the reconciler has no row to heal, so stage 1 retries once before giving up.
 * (No-op when unconfigured also returns true — there's nothing to persist.)
 */
async function reportSubmission(
  env: Env,
  args: { hash: string; paymentId?: string; outcome: "pending_unknown" | "success" | "failed" }
): Promise<boolean> {
  if (!env.PAYIN_NOTIFY_URL) return true; // not configured → no-op (nothing to persist)
  const base = env.PAYIN_NOTIFY_URL.replace(/\/+$/, "");
  const url = `${base}/payment-api/relayer-submissions`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (env.WALLETAPP_PAYIN_NOTIFY_TOKEN) headers["X-Relayer-Token"] = env.WALLETAPP_PAYIN_NOTIFY_TOKEN;
  const body = JSON.stringify({
    txHash: args.hash,
    outcome: args.outcome,
    network: env.NETWORK,
    ...(args.paymentId ? { paymentId: args.paymentId } : {}),
  });
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(url, { method: "POST", headers, body, signal: controller.signal });
    clearTimeout(timeoutId);
    console.log(`[RelayerSubmission] ${args.outcome} tx=${maskHash(args.hash)} HTTP ${res.status}`);
    return res.ok;
  } catch {
    // Coarse tag only — never the raw error text (P3: keep the logging contract
    // tight). A network/timeout failure here is benign; the reconciler is the
    // backstop for any row we couldn't persist.
    console.error(`[RelayerSubmission] ${args.outcome} tx=${maskHash(args.hash)} network_error`);
    return false;
  }
}

/**
 * Background finalizer for a submitted tx (A+D weak-network fix, methods A+D).
 * Runs via c.executionCtx.waitUntil so the HTTP response already returned
 * PENDING — Cloudflare keeps this alive ~30s after the client disconnects,
 * enough for one Stellar ledger close (~5s).
 *
 * TWO-STAGE WRITE (codex P1#1): the FIRST thing it does is record the row as
 * pending_unknown (with one quick retry on a transient failure, so a flaky
 * network blip doesn't silently leave the reconciler nothing to heal). If this
 * isolate is then recycled or the poll times out, the row still exists for the
 * reconciler cron (Task 3) to finalize by tx_hash. The poll here is only the
 * fast path.
 *
 * Even if BOTH stage-1 writes fail, correctness is preserved: relayer_submissions
 * is OBSERVABILITY, not the settlement path. The tx (if it landed) is still
 * settled by /payin recheck + getEvents cron + Mercury webhook keyed on the
 * on-chain memo. The only loss in that worst case is one row's ops-visibility.
 *
 * ⚠️ NOTE: A+D does NOT prevent on-chain double-debit on client retry. The
 * first send can land on-chain, the client can disconnect, and a retry can send
 * (and debit) a SECOND tx. memo+CAS in settleContractPayin only prevents
 * double-SETTLEMENT to the merchant, not a second on-chain debit. This is a
 * known residual risk; the root fix is pre-sign idempotency (plan B), not done
 * here. Do not "fix" this by suppressing the early return — that reintroduces
 * the weak-network failure this whole change exists to remove.
 */
async function finalizeSubmission(
  env: Env,
  hash: string,
  paymentId?: string,
  fromAddress?: string
): Promise<void> {
  // Stage 1: record pending_unknown immediately (even with no paymentId — codex
  // P2#8). This is the row the reconciler heals if the poll below never lands,
  // so retry once on a transient failure before moving on (codex P1).
  const stage1ok = await reportSubmission(env, { hash, paymentId, outcome: "pending_unknown" });
  if (!stage1ok) {
    await reportSubmission(env, { hash, paymentId, outcome: "pending_unknown" });
  }

  // Fast path: poll for finality within the waitUntil budget (~25s of ~30s).
  const rpcUrl = getRpcUrl(env.NETWORK);
  const server = new rpc.Server(rpcUrl);
  let finalStatus: "SUCCESS" | "FAILED" | "PENDING" = "PENDING";
  try {
    let r = await server.getTransaction(hash);
    const start = Date.now();
    while (r.status === "NOT_FOUND" && Date.now() - start < 25000) {
      await new Promise((res) => setTimeout(res, 1000));
      r = await server.getTransaction(hash);
    }
    if (r.status === "SUCCESS") finalStatus = "SUCCESS";
    else if (r.status === "FAILED") finalStatus = "FAILED";
    // else still NOT_FOUND → leave PENDING; reconciler cron picks it up.
  } catch {
    // RPC error during polling → stay PENDING; reconciler is the backstop.
    // Coarse tag only (P3) — the raw RPC error text is noisy and adds nothing.
    console.error(`[FinalizeSubmission] tx=${maskHash(hash)} poll_error`);
  }

  if (finalStatus === "SUCCESS") {
    await reportSubmission(env, { hash, paymentId, outcome: "success" });
    // SUCCESS + paymentId → notify the backend /payin (the original fast-path).
    if (paymentId) await notifyPayinBackend(env, paymentId, hash, fromAddress);
  } else if (finalStatus === "FAILED") {
    await reportSubmission(env, { hash, paymentId, outcome: "failed" });
  }
  // PENDING → already recorded pending_unknown in stage 1; reconciler finalizes.
}

// ============================================================================
// API Endpoints
// ============================================================================

// Health check
app.get("/", (c) => {
  return c.json({
    status: "ok",
    service: "smart-account-relayer-proxy",
    network: c.env.NETWORK,
    mode: isSelfSponsored(c.env) ? "self-sponsored" : "oz-channels",
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
 * Mode is controlled by SPONSOR_MODE env var:
 * - "1" or "true": self-sponsored (requires SPONSOR_SECRET_KEY)
 * - "0", "false", or unset: OZ Channels
 */
app.post("/", async (c) => {
  const ip = getClientIP(c.req.raw);
  const selfSponsored = isSelfSponsored(c.env);

  try {
    const body = await c.req.json<{
      func?: string;
      auth?: string[];
      xdr?: string;
      // Optional Rozo payment context. When present (and self-sponsored), the
      // worker fire-and-forgets a /payin notify to the Rozo backend the moment
      // the tx lands on-chain (SUCCESS). Purely additive: absent → old behavior.
      paymentId?: string;
      fromAddress?: string;
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
    // Self-sponsored mode (SPONSOR_MODE = "1" or "true")
    // ========================================================================
    if (selfSponsored) {
      if (!c.env.SPONSOR_SECRET_KEY) {
        return c.json(
          {
            success: false,
            error: "Self-sponsored mode enabled but SPONSOR_SECRET_KEY is not configured.",
          },
          500
        );
      }

      console.log(`Self-sponsored mode (${c.env.NETWORK})...`);

      try {
        if (hasXdr) {
          const result = await submitSelfSponsoredXdr(c.env, body.xdr!);
          // Submission succeeded → result.status is PENDING (we no longer block
          // for finality). Resolve finality + record relayer_submissions + notify
          // /payin entirely off the request path in finalizeSubmission. ALWAYS
          // runs (records by tx_hash even with no paymentId — codex P2#8). The
          // response returns immediately so weak-network clients don't need the
          // connection to survive the on-chain wait.
          c.executionCtx.waitUntil(
            finalizeSubmission(c.env, result.hash, body.paymentId, body.fromAddress)
          );
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
          c.executionCtx.waitUntil(
            finalizeSubmission(c.env, result.hash, body.paymentId, body.fromAddress)
          );
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
    // OZ Channels mode (default)
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

    try {
      if (hasXdr) {
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
      throw submitError;
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

  return c.json({
    success: true,
    data: {
      clientIP: ip,
      network: c.env.NETWORK,
      mode: isSelfSponsored(c.env) ? "self-sponsored" : "oz-channels",
      hasKey: !!apiKey,
      keyCreatedAt: apiKey?.createdAt,
    },
  });
});

// ============================================================================
// Worker Export
// ============================================================================

export default {
  fetch: app.fetch,
};
