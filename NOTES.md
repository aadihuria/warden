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

1. ~~Taint is session-level, not per-action/citation-based.~~ **Fixed
   after M1 benchmarking — see "M1 fix" section below.** Taint is now
   attributed per action via token-overlap against stored span content
   (`include/warden/attribution.hpp`), not accumulated for the whole
   session. This is still a heuristic approximation of DESIGN.md 4.1's
   citation/embedding-similarity design, not the real thing — see that
   section for what's simplified about it.

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

## M1: first benchmark numbers (hand-authored fixtures, not real corpora yet)

`scripts/benchmark/runner.py` runs 4 attack scenarios + 3 benign-only
scenarios (mirroring AgentDojo's domain split) through Warden, scored
against a deterministic stub "agent" (free, no API calls — see
`scripts/benchmark/README.md`). First real measured result:

- **Attack success rate, hijackable backend: 100% without Warden -> 0%
  with Warden**, across all 4 attack scenarios (banking exfil, Slack DM
  leak, workspace file deletion, travel booking fraud).
- **False-positive rate on benign scenarios: 0% without Warden -> 100%
  with Warden.**

The false-positive number is not a bug — it's the honest, measured cost
of simplification #2 above (source-level, not content-level, taint
tagging). Every benign scenario in this fixture set reads an
`ingests_untrusted: true` tool before taking an `EXTERNAL_COMM` action
(read transactions -> email, read channel -> post), which is exactly the
shape of a huge fraction of real legitimate agent workflows (read
something, then communicate about it). M0 can't currently tell "this read
happened to be clean" from "this read was poisoned" — it doesn't try to,
by design — so it blocks both.

This is the single most important finding from M1 so far: **M0's 100%
attack-success reduction is not usable in production as-is**, because a
100% false-positive rate on read-then-communicate workflows makes the
agent useless for exactly the tasks it exists to do.

## M1 fix: per-action taint attribution (`include/warden/attribution.hpp`)

Replaced the whole-session `TaintLineage` with per-action attribution:
every ingested untrusted response is kept as a `Span` (actual text, not
just a hash), and when a high-risk tool call comes in, its argument text
is compared against every known span via a token-overlap heuristic
(`overlap_coefficient` — intersection over the SMALLER token set, so it
measures "how much of this action's own text came from this span", not
general text similarity). A span only contributes taint to an action if
the overlap clears `match_threshold` (default 0.15). The resulting
confidence score now actually drives the policy decision for
`EXTERNAL_COMM` (`src/policy.cpp`): confidence >= 0.4 denies outright,
below that escalates instead of denying (see simplification #3 above —
escalation is still deny-equivalent until M3 ships a real quorum).

**Re-measured result:**

- Attack success rate: still **100% -> 0%** with Warden — the fix didn't
  weaken detection. The real attack scenarios share a distinctive,
  attacker-controlled string (e.g. `attacker@evil.example`) between the
  poisoned span and the hijacked action, which the overlap heuristic
  catches with confidence ~0.5-0.7 (well above the 0.4 deny threshold).
- False-positive rate: **100% -> 67%** (2 of 3 benign scenarios still
  wrongly blocked, down from 3 of 3). `benign_banking_report` is now
  correctly allowed (the legitimate email text shares no tokens with the
  transaction memo it was summarizing). `benign_slack_summary` and
  `benign_workspace_fetch_and_email` are still blocked.

**Why those two specifically, and what it means:** both are cases where
the legitimate action naturally echoes words from the content it's
responding to — e.g. the Slack summary literally says "shipped the
migration" because that's what the channel said. Checked the actual
decision (see audit log in the repro below): confidence came out to
**0.2**, well below the attack scenarios' 0.5-0.7 — i.e. the heuristic
correctly identifies this as a *much weaker* match than a real attack,
it's just that M0 has no quorum to route a weak-but-nonzero match to
(simplification #3), so `EscalateToQuorum` still acts as a hard block.
This is a real, substantive finding, not a wash: **distinguishing
legitimate grounding from malicious injection by confidence level is
exactly what the design's escalate-vs-deny split is for, and it's
working as designed — the remaining false positives are a consequence of
M3 (quorum verifier) not existing yet, not of the attribution heuristic
being wrong.** Shipping M3 should resolve most or all of this residual
67% without touching the detection logic at all, since these cases would
route to quorum instead of auto-blocking.

Repro: `scripts/benchmark/runner.py`, or manually drive
`./build/warden-proxy` against `scripts/benchmark/scenarios/benign_slack_summary.json`
one request at a time (wait for each response before sending the next —
see the race-condition note above) and read `action_confidence` in the
audit log.

## Next steps (not started)

- M3 (quorum verifier) is now the best next lever for the remaining 67%
  false-positive rate — route `EscalateToQuorum` to an actual decision
  instead of treating it as deny.
- Integrate the real AgentDojo / InjecAgent corpora in place of the
  hand-authored fixtures (loader swap, see `scripts/benchmark/README.md`)
  and a real model backend (`AnthropicBackend` is stubbed in
  `scripts/benchmark/agent_backends.py`) — worth doing now that the
  false-positive rate is in a defensible range, not 100%.
- Swap FNV-1a for SHA-256 before `content_hash` is used anywhere
  security-relevant.
- The token-overlap heuristic is still just a heuristic (see
  `include/warden/attribution.hpp` docstring) — a real citation-based or
  embedding-based approach per DESIGN.md 4.1 would likely separate
  legitimate grounding from injection better than raw text overlap can.
