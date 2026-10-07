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

## M3: quorum verifier (`include/warden/quorum.hpp`, `verifiers.hpp`)

Implemented the N-verifier fan-out from DESIGN.md 4.3: `EscalateToQuorum`
now routes to a real decision via `QuorumVerifier` instead of being
treated as deny. Three deterministic, free stub verifiers (stand-ins for
real model-backed verifiers, which cost API calls — see
`scripts/benchmark/agent_backends.py::AnthropicBackend`):

- `KeywordInjectionVerifier` — flags classic injection phrasing in the
  evidence excerpts.
- `ArgumentDestinationVerifier` — checks the action's own `to`/`channel`
  field against a configured trusted-destination allowlist (abstains if
  the action has no such field, e.g. a file path or hotel ID).
- `AlwaysApproveVerifier` — explicit placeholder for a third real
  verifier; not a security control on its own (see its class docstring).

Quorum rule: any single Deny blocks the action outright (fail closed on
disagreement); Allow needs >= `required_approvals` (default 2) Approves
with zero Denies; anything else (not enough signal, no denies) escalates
to human — which, like `EscalateToQuorum` before it, has no real channel
yet and is currently treated as blocked by the proxy.

**Also corrected a real documentation error in DESIGN.md while building
this**: section 4.3 originally said verifiers are isolated by being
denied the untrusted context, but a verifier that can see *nothing* of
the actual content can't judge anything — that claim didn't survive
contact with actually building it. The real isolation property, now
fixed in DESIGN.md: verifiers have **zero tool-execution capability**,
so a verifier whose own reasoning gets hijacked by content in its
evidence can only cast a bad vote, never take a real action.

**Re-measured result after wiring the quorum in:**

- False-positive rate: **67% -> 0%**. Both remaining false positives from
  the M1 fix (weak-confidence legitimate content reuse) now correctly
  route to quorum instead of being auto-blocked, and the quorum approves
  them (`ArgumentDestinationVerifier` sees a trusted channel/recipient,
  `KeywordInjectionVerifier` finds no injection phrasing, 2-of-3 with
  zero denies -> Allow).
- Attack success rate: **first run regressed to 50%** (2 of 4 attack
  scenarios got through) before a fix — see below. Final: back to 0%.

**The regression, and what it actually shows:** `attack_travel_booking_fraud`
and `attack_workspace_doc_leak` initially got through the quorum. Root
cause, found by actually reading the evidence text (not assumed):
`ArgumentDestinationVerifier` has nothing to check for `book_reservation`
(no `to`/`channel` field — it abstains) or `delete_file` (same), so for
those risk classes the entire quorum outcome rode on
`KeywordInjectionVerifier` alone — and its marker list was too narrow
("ignore the user" didn't match "ignore the requested hotel" or "ignore
the summary request"). Fixed by broadening the marker list to the
general phrasing family ("ignore the ...", "disregard previous", "new
instructions:"), which brought attack success back to 0% on this fixture
set.

**This is not "solved," and the numbers shouldn't be read that way.**
Two real, unresolved facts:

1. Keyword matching is structurally evadable by paraphrase — a bigger
   list is not a fix, it's a slower loss. Both the broadened list here
   and literally any fixed-phrase list share this property. The actual
   fix is a model-backed verifier that reasons about intent rather than
   matching strings, which is exactly why DESIGN.md specifies "different
   model, not just a rule" for the real verifiers and why
   `AnthropicBackend`/real verifier integration is still unimplemented,
   not a nice-to-have.
2. Any action with no destination-like field (financial bookings, file
   deletions, code execution) currently has only ONE real independent
   signal (keywords) backing it, not three — `AlwaysApproveVerifier`
   contributes nothing and `ArgumentDestinationVerifier` abstains. The
   quorum's 2-of-3 threshold is currently satisfiable by one real
   verifier agreeing with a no-op stub for this whole class of action.
   This is a genuine coverage gap, not a wording issue, and a real
   verifier (or a destination-style check generalized to "does this
   action's target resource/amount look consistent with the stated
   task") is needed before this risk class has real multi-signal
   coverage.

Measuring this and writing it down honestly — rather than stopping at
the clean 0%/0% final numbers — is the actual point of having a
benchmark harness at all.

## Next steps (not started)

- Replace `AlwaysApproveVerifier` with a real second signal for
  destination-less risk classes (FINANCIAL, CODE_EXEC, IRREVERSIBLE_WRITE
  without a recipient field) — the current quorum has a real coverage
  gap there (see M3 section above), not just for this fixture set.
- Integrate a real model-backed verifier (`AnthropicBackend` stub in
  `scripts/benchmark/agent_backends.py`) — this is the actual fix for
  keyword-evasion, not a longer marker list.
- Integrate the real AgentDojo / InjecAgent corpora in place of the
  hand-authored fixtures (loader swap, see `scripts/benchmark/README.md`).
- Swap FNV-1a for SHA-256 before `content_hash` is used anywhere
  security-relevant.
- M4: replace the single-node JSON-lines audit log with the replicated,
  hash-chained CRDT ledger from DESIGN.md 4.4 — now has real content to
  carry (quorum votes, not just allow/deny).
