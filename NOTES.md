# M0 implementation notes

Status: M0 deliverable from DESIGN.md is working and demonstrated —
"point Claude at a filesystem + web-fetch MCP server through Warden;
demonstrate a crafted poisoned webpage causes a deny/escalate that an
unprotected setup would have allowed." See `scripts/demo_driver.py` for a
reproducible end-to-end run against a toy MCP server
(`scripts/fake_mcp_server.py`), plus a side-by-side run of the same toy
server with no Warden in front (unprotected baseline) to confirm the
comparison is real, not assumed.

## What's implemented

- `include/warden/taint.hpp` + `src/taint.cpp` — trust lattice
  (`UNTRUSTED_EXTERNAL < UNTRUSTED_INTERNAL < OPERATOR < PRINCIPAL`),
  `ProvenanceEnvelope`, `TaintLineage` with a join-semilattice `absorb()`
  (taint only ever gets worse, never washes out — covered by
  `tests/test_taint.cpp`).
- `include/warden/policy.hpp` + `src/policy.cpp` — fixed taint-aware
  policy rules matching the examples in DESIGN.md section 4.2 (covered by
  `tests/test_policy.cpp`, 14/14 passing under `-fsanitize=address,undefined`).
- `src/proxy_main.cpp` — a working MCP stdio proxy: spawns the real
  downstream MCP server as a child process, forwards all traffic
  transparently except `tools/call`, which goes through the policy
  engine; blocked calls never reach the child.

## Known M0 simplifications (intentional, not oversold)

1. **Taint is session-level, not per-action/citation-based.** DESIGN.md's
   full design (4.1, item 2) calls for parsing citation `span_id`s out of
   the agent's own reasoning trace so taint is attributed to the specific
   action it justified, with a classifier fallback. M0 approximates this
   with a single running `TaintLineage` for the whole session: once any
   untrusted content has been read, every subsequent high-risk action is
   evaluated against that worst-case taint until the session ends. This
   is the correct fail-closed default and is sufficient for the M0
   deliverable, but it over-blocks a long session that reads one
   untrusted page early and does unrelated high-risk work much later.
   Per-action citation-based taint is scheduled for M1/M2 alongside the
   injection-benchmark work.

2. **Trust tier is assigned per tool/source, not per content payload.**
   `fetch_url` is always `UNTRUSTED_EXTERNAL` regardless of whether a
   given page actually contains a visible injection payload — this is
   deliberate (a content classifier can't be trusted to catch every
   payload, so the safe default taints by source type), but it means a
   completely benign fetched page still taints the session. This is
   expected and matches the "fail closed" principle in DESIGN.md, not a
   bug — see the comments in `scripts/demo_driver.py` for a case where a
   first draft of the demo incorrectly assumed otherwise.

3. **`EscalateToQuorum` has no quorum to escalate to yet.** M0 has no
   quorum verifier (that's M3). The proxy currently treats any non-Allow
   decision as a hard block and returns a synthesized MCP error
   explaining why, with the reason string noting that real escalation
   isn't wired up yet.

4. **`content_hash` uses FNV-1a, not a cryptographic hash.** Fine for an
   M0 audit log; DESIGN.md section 4.4's hash-chained ledger needs a real
   digest (e.g. SHA-256) before the chain is relied on for tamper
   evidence — don't reuse this as-is for M4.

5. **Audit log is a single-node, local JSON-lines file**, not the
   replicated CRDT ledger from DESIGN.md 4.4. That's M4.

## A real bug found and fixed during M0, worth remembering

The first version of the end-to-end demo piped both JSON-RPC requests
into the proxy's stdin back-to-back with no synchronization. That raced
the policy decision for `send_email` (request 2) against the taint-tagging
of the `fetch_url` response (request 1, processed by a separate reader
thread), and the race lost — send_email got evaluated against a
still-clean session and went through.

This isn't an MCP protocol issue: a real agent is sequential by
construction (it observes a tool's result before deciding the next call),
so this exact race doesn't occur in real usage. But it's a reminder that
the proxy's correctness implicitly depends on request/response ordering
per logical session, and that assumption should be made explicit (and
probably asserted/tested) before this is extended to handle concurrent
tool calls or multiple simultaneous agent sessions in a later milestone.
`scripts/demo_driver.py` now drives the proxy the way a real client
would — one call, read its response, then the next — and documents why.

## Next steps (not started)

- M1: integrate against a real published injection benchmark
  (AgentDojo / InjecAgent — re-verify current availability, see
  DESIGN.md open question #1) to get a defensible attack-success-rate
  number instead of only this hand-crafted demo.
- Swap FNV-1a for SHA-256 before `content_hash` is used anywhere
  security-relevant.
- Per-action citation-based taint propagation (DESIGN.md 4.1, item 2).
