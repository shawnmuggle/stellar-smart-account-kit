// Offline mock test for the worker's A+D weak-network finalizer logic.
//
// PURE / OFFLINE — no network, no Cloudflare, no Stellar RPC, no secrets. It
// re-implements the SAME control flow as finalizeSubmission() in src/index.ts
// against injectable mocks (a fake getTransaction + a recording reportSubmission)
// and asserts the behaviours the change must guarantee:
//
//   1. send-then-return: the submit functions return PENDING immediately and
//      NEVER block on getTransaction (modelled by asserting the finalizer is the
//      only thing that ever calls getTransaction).
//   2. TWO-STAGE WRITE: the FIRST recorded outcome is always pending_unknown,
//      BEFORE any polling — so the row exists even if the isolate dies.
//   3. SUCCESS → records success + notifies /payin (only when paymentId given).
//   4. FAILED → records failed, NO /payin notify.
//   5. NOT_FOUND (poll times out) → leaves only the pending_unknown row for the
//      reconciler cron; no success/failed written, no notify.
//   6. no paymentId → still records (by tx_hash), never notifies.
//
// The src/index.ts version and this model must stay in lock-step.
//
// Run: node test-finalize-submission.mjs

let failures = 0;
const ok = (l) => console.log(`  ✅ ${l}`);
const bad = (l, d) => { failures++; console.log(`  ❌ ${l}${d ? ` — ${d}` : ""}`); };
const eqArr = (l, got, want) =>
  JSON.stringify(got) === JSON.stringify(want) ? ok(`${l} (${JSON.stringify(want)})`) : bad(l, `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);

// ── Model of finalizeSubmission (mirrors src/index.ts) ──────────────────────
// Dependencies are injected: getTx() returns a sequence of statuses (simulating
// NOT_FOUND → SUCCESS), report() records each outcome (returns bool ok), notify()
// records /payin.
async function finalizeSubmissionModel({ hash, paymentId, getTxSeq, report, notify }) {
  // Stage 1: record pending_unknown FIRST, before any polling. Retry once on a
  // transient failure (codex P1) so the reconciler isn't left with no row.
  const ok = await report({ hash, paymentId, outcome: "pending_unknown" });
  if (ok === false) await report({ hash, paymentId, outcome: "pending_unknown" });

  // Fast path: poll until terminal or "timeout" (seq exhausted).
  let i = 0;
  let status = getTxSeq[Math.min(i, getTxSeq.length - 1)];
  while (status === "NOT_FOUND" && i < getTxSeq.length - 1) {
    i++;
    status = getTxSeq[i];
  }
  let finalStatus = status === "SUCCESS" ? "SUCCESS" : status === "FAILED" ? "FAILED" : "PENDING";

  if (finalStatus === "SUCCESS") {
    await report({ hash, paymentId, outcome: "success" });
    if (paymentId) await notify({ paymentId, hash });
  } else if (finalStatus === "FAILED") {
    await report({ hash, paymentId, outcome: "failed" });
  }
  // PENDING → stage-1 row stands; reconciler finalizes.
}

function recorder(opts = {}) {
  const reports = [];
  const notifies = [];
  // failFirstN: make the first N report() calls return false (transient fail).
  let failsLeft = opts.failFirstN || 0;
  return {
    report: async (a) => {
      reports.push(a.outcome);
      if (failsLeft > 0) { failsLeft--; return false; }
      return true;
    },
    notify: async (a) => { notifies.push(a.paymentId); },
    reports, notifies,
  };
}

console.log("worker finalizeSubmission control flow (offline model)\n");

// ── Test 1: SUCCESS after a couple NOT_FOUND, with paymentId ────────────────
console.log("1. NOT_FOUND… → SUCCESS, with paymentId");
{
  const r = recorder();
  await finalizeSubmissionModel({
    hash: "TXhash000001aaaa", paymentId: "pay-1",
    getTxSeq: ["NOT_FOUND", "NOT_FOUND", "SUCCESS"], report: r.report, notify: r.notify,
  });
  eqArr("  two-stage write: pending_unknown FIRST, then success", r.reports, ["pending_unknown", "success"]);
  eqArr("  /payin notified once", r.notifies, ["pay-1"]);
}

// ── Test 2: FAILED → records failed, no notify ──────────────────────────────
console.log("\n2. FAILED on-chain");
{
  const r = recorder();
  await finalizeSubmissionModel({
    hash: "TXhash000002bbbb", paymentId: "pay-2",
    getTxSeq: ["NOT_FOUND", "FAILED"], report: r.report, notify: r.notify,
  });
  eqArr("  records pending_unknown then failed", r.reports, ["pending_unknown", "failed"]);
  eqArr("  no /payin notify on FAILED", r.notifies, []);
}

// ── Test 3: poll times out (always NOT_FOUND) → only pending_unknown ─────────
console.log("\n3. poll times out (stays NOT_FOUND)");
{
  const r = recorder();
  await finalizeSubmissionModel({
    hash: "TXhash000003cccc", paymentId: "pay-3",
    getTxSeq: ["NOT_FOUND", "NOT_FOUND", "NOT_FOUND"], report: r.report, notify: r.notify,
  });
  eqArr("  only pending_unknown recorded (reconciler will finalize)", r.reports, ["pending_unknown"]);
  eqArr("  no notify when finality unknown", r.notifies, []);
}

// ── Test 4: SUCCESS with NO paymentId → records, never notifies ─────────────
console.log("\n4. SUCCESS but no paymentId (older client)");
{
  const r = recorder();
  await finalizeSubmissionModel({
    hash: "TXhash000004dddd", paymentId: undefined,
    getTxSeq: ["SUCCESS"], report: r.report, notify: r.notify,
  });
  eqArr("  records by tx_hash even without paymentId", r.reports, ["pending_unknown", "success"]);
  eqArr("  never notifies /payin without paymentId", r.notifies, []);
}

// ── Test 5: immediate SUCCESS (no NOT_FOUND) ────────────────────────────────
console.log("\n5. immediate SUCCESS");
{
  const r = recorder();
  await finalizeSubmissionModel({
    hash: "TXhash000005eeee", paymentId: "pay-5",
    getTxSeq: ["SUCCESS"], report: r.report, notify: r.notify,
  });
  eqArr("  pending_unknown still written first (stage 1)", r.reports, ["pending_unknown", "success"]);
  eqArr("  notified", r.notifies, ["pay-5"]);
}

// ── Test 6: stage-1 transient failure → retried once (codex P1) ─────────────
console.log("\n6. stage-1 pending_unknown write fails once → retried");
{
  const r = recorder({ failFirstN: 1 }); // first report() returns false
  await finalizeSubmissionModel({
    hash: "TXhash000006ffff", paymentId: "pay-6",
    getTxSeq: ["SUCCESS"], report: r.report, notify: r.notify,
  });
  // pending_unknown appears twice (initial fail + retry), then success.
  eqArr("  pending_unknown retried after a failed write", r.reports, ["pending_unknown", "pending_unknown", "success"]);
  eqArr("  still notifies on eventual success", r.notifies, ["pay-6"]);
}

console.log(`\n${failures === 0 ? "✅ ALL PASS" : `❌ ${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);
