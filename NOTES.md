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

## Real model-backed verifier (`include/warden/anthropic_verifier.hpp`)

Implemented `AnthropicVerifier`: calls the real Anthropic Messages API
(model defaults to `claude-haiku-4-5-20251001` — deliberately a small/
cheap/fast model, since this is a bounded classification task, not open-
ended reasoning) with the proposed action + evidence excerpts, asks for a
strict JSON vote, and parses it. The system prompt explicitly instructs
the model to treat evidence excerpts as DATA, never as instructions —
the same "contained reasoning" framing as the stub verifiers, but backed
by actual judgment instead of pattern matching, which is the real fix for
the two gaps the stub quorum left open (keyword-evasion by paraphrase,
no real second signal for destination-less risk classes).

Wired into `proxy_main.cpp` as the quorum's third verifier, auto-
upgrading from the free `AlwaysApproveVerifier` stub the moment
`ANTHROPIC_API_KEY` is set in the environment — no other code change
needed. No key -> proxy behaves exactly as before (free, deterministic);
key present -> every quorum-escalated action makes one real, billed API
call. Verified the live code path end-to-end with a deliberately invalid
key: the HTTP call fires, a 401 comes back, the verifier abstains with a
clear reason, and the quorum still resolves correctly around that
abstain — no crash, no silent failure. Have not yet run it against a
*valid* key / the real benchmark suite — that's a deliberate, explicit
choice (real API cost), left for whoever runs it next. Fail-safe by
construction: any HTTP error, non-200 response, or unparseable model
output abstains rather than silently approving or crashing the proxy.

## M4: CRDT audit ledger (`include/warden/ledger.hpp`)

Implemented the mergeable, tamper-evident audit ledger from DESIGN.md
4.4: `CrdtLedger` is a per-replica, hash-chained, content-addressed
append log (each event's `content_hash` is a real SHA-256 — vendored
Brad Conte's public-domain implementation, `third_party/sha256.{h,c}` —
derived from every other field, so it doubles as the event's unique id).
`merge()` is a plain OR-Set union keyed by `content_hash`: tested
directly (not just asserted) for commutativity, associativity, and
idempotence, plus an explicit partition-heal scenario (two replicas
record independently, merge with no loss or duplication, re-merging is a
no-op). `find_tampered_event()` recomputes every event's hash and checks
per-replica chain linkage; tested against both a corrupted payload and a
deleted middle event via explicit test-only corruption hooks, not just
trusted to work.

**Real bug found and fixed while building this**: the sanitizer build
caught genuine undefined behavior in the vendored SHA-256 code itself
(`third_party/sha256.c:49`, now fixed with a comment) — a `BYTE` getting
promoted to signed `int` before a 24-bit left shift, UB in C whenever the
byte's top bit is set. Not a Warden bug, but it would have shipped
silently if the ASan/UBSan build hadn't been in place; fixed rather than
suppressed, since this hash feeds the ledger's tamper-evidence chain.
Verified against the standard SHA-256 known-answer test vectors for `""`
and `"abc"` before and after.

`proxy_main.cpp`'s `AuditLog` now writes through a real `CrdtLedger`
instead of a flat JSON-lines file — every line persisted is a real ledger
event (`replica_id`, `lamport_clock`, `prev_hash`, `content_hash`,
`payload`). `scripts/ledger/attribute.py` reads a persisted log back,
independently re-verifies the entire hash chain in Python (not trusting
the C++ process that wrote it), and walks a denied/escalated decision's
`matched_span_ids` back to the exact `ingest` event (tool + trust tier)
that caused it — the attribution tool DESIGN.md 4.4 asks for. Verified
both halves for real: ran it against a genuine audit log from the demo
and got correct attribution output, then hand-tampered a copy of the
file (rewrote a `deny` decision to `allow`, simulating an attacker
editing the log after the fact) and confirmed the tool catches it and
exits non-zero.

**What's NOT implemented**: actual network replication between live
Warden instances (gRPC sync, discovery, etc.) at the time this section
was first written. **Fixed below.**

## Network replication (`include/warden/replication.hpp`)

Implemented the actual transport layer that moves ledger events between
two live, separate Warden processes — this was the one explicitly-named
gap left at the end of M4. Deliberately NOT gRPC, despite DESIGN.md's
original tech-stack section mentioning it: the protocol surface needed
is exactly two routes (`GET /ledger/events`, `POST /ledger/sync`), so a
hand-rolled HTTP/1.1 server over raw POSIX sockets (~100 lines) is a
smaller, more auditable trusted-computing base than pulling in a full
RPC framework for two endpoints — consistent with the project's general
preference for hand-rolled-where-small over dependency-where-heavy (see
the vendored SHA-256 instead of a crypto library, for the same reason).
`fetch_peer_events_json` on the client side reuses the already-vendored
libcurl rather than hand-rolling an HTTP client too, since libcurl was
already a dependency for the Anthropic verifier.

Server binds to `127.0.0.1` only, not `0.0.0.0` — replication is for
trusted peer Warden instances an operator deploys together, not a public
endpoint; exposing it beyond loopback (e.g. across hosts) would need real
authentication between replicas, which is explicitly out of scope here
and should be treated as a prerequisite before this is ever bound to a
non-loopback address.

`CrdtLedger::merge_events()` is a new primitive (returns only the
actually-new events, not just merges blindly) that both `merge(other)`
and the replication layer share — the network layer calls it directly on
events received over HTTP, and `AuditLog::sync_with_peers()` persists
only the delta to the on-disk log rather than rewriting everything.

**Verified for real, not just in unit tests**: `scripts/replication_demo.py`
starts two actual, separate `warden-proxy` processes on different ports,
each recording one decision completely independently (simulating two
Warden deployments that have never talked to each other), triggers a
real `POST /ledger/sync` HTTP call between them, and confirms both
converge to the identical combined event set — then independently
re-verifies the merged log's hash chain via `scripts/ledger/attribute.py`
in a separate process, proving a log containing events from two
different replicas (received over a real network call, not an in-memory
merge) still verifies correctly. Added to CI (`.github/workflows/ci.yml`)
so this is checked on every push, not just asserted once locally.

**What's still not here**: peer discovery (peers are statically
configured, not discovered), authentication between replicas (anyone who
can reach the loopback port can call `/ledger/sync`), and automatic
periodic syncing (sync is triggered on demand via `POST /ledger/sync`,
not on a background timer — a trivial addition, a thread calling the
same `sync_with_peers` on an interval, left undone because a timer-based
test is inherently flakier to verify deterministically than an
explicitly-triggered one).

## Expanded benchmark: more scenarios, a real policy bug found, and latency numbers

The original fixture set (4 attack + 3 benign scenarios) was small enough
that a clean 0%/0% result wasn't fully trustworthy — too easy to have
accidentally hand-picked cases that happened to work. Expanded to 16
scenarios (8 attack, 8 benign) across 6 domains (added calendar, CRM,
devops to the original banking/Slack/workspace/travel), including two
kinds of cases specifically designed to break things rather than confirm
they work:

- **Evasion attacks**: injection phrasing that deliberately avoids every
  marker in `KeywordInjectionVerifier`'s list, to honestly test whether
  detection depends on exact keyword matching rather than real
  understanding.
- **Benign scenarios across all risk classes**, not just `EXTERNAL_COMM`
  — added clean `FINANCIAL`, `CODE_EXEC`, and `IRREVERSIBLE_WRITE` cases,
  which the original fixture set never exercised at all.

**This immediately found a real bug, not a test artifact.** Two new
benign scenarios (calendar, CRM) got wrongly blocked — a new 25%
false-positive rate, not the 0% from before. Root cause, confirmed by
tracing the actual decision in the audit log rather than guessing: a
shortcut in `src/policy.cpp` denied `EXTERNAL_COMM` actions directly,
bypassing the quorum entirely, whenever taint-attribution confidence was
>= 0.4 ("strong textual overlap = probably a real injection citation").
That reasoning was wrong in an important way: a LEGITIMATE action that
relays something the agent genuinely just read — forwarding a meeting
link, referencing a ticket number — produces exactly the same high
overlap confidence, because the agent is correctly copying real content
verbatim. High confidence means "this action is clearly connected to
this span," not "this connection is malicious." Only the quorum's
destination-aware check (`ArgumentDestinationVerifier`) can actually
tell those apart, and the confidence shortcut was skipping it—silently
throwing away the one signal that mattered, for every single
high-confidence case, the whole time the quorum has existed.

**Fixed properly, not patched around**: removed the confidence-gated
direct-deny path entirely. Every tainted `EXTERNAL_COMM` action now
always escalates to the quorum, which already has the right signal to
resolve it correctly. This is a general, principled fix (restores the
actual point of building a multi-signal quorum in M3 — not letting a
single heuristic bypass it), not a fixture-specific patch; verified by
re-running the full expanded suite, not just the two scenarios that
exposed it.

**Final numbers on the expanded (16-scenario, 6-domain) set:**

- Core attack success rate: **100% → 0%** (N=7 core attack scenarios —
  same result as the original smaller set, now on more than double the
  domains and including real evasion-resistant phrasing variants)
- Stress/evasion attack success rate: **100%** (N=1) — the
  destination-less, keyword-evading `attack_evasion_destinationless`
  scenario succeeds against the stub quorum exactly as predicted in the
  M3 notes above. Reported honestly, excluded from the CI regression
  gate (which only covers the core/non-adversarial set) rather than
  either hidden or allowed to fail CI for a known, already-documented
  limitation.
- False-positive rate: **0%** (N=8, across all 6 risk classes with a
  destination field tested, plus FINANCIAL/CODE_EXEC/IRREVERSIBLE_WRITE
  which have none)

**Latency** (never measured before, despite DESIGN.md's evaluation plan
asking for it): steady-state per-call overhead through Warden is
**p50 0.9ms / p95 1.2ms / p99 1.25ms** (well under DESIGN.md's <20ms/50ms
targets) — measured separately from cold-start/first-call latency
(~80ms, dominated by subprocess spawn time in the benchmark harness
itself, not proxy overhead) so process-startup noise doesn't inflate the
number that actually matters.

## ThreadSanitizer run + real throughput numbers

Added a `WARDEN_ENABLE_TSAN` CMake option (mutually exclusive with
ASan — they can't run in the same build) and ran the full test suite
plus the most concurrency-heavy real path in the codebase (the
replication server's accept-loop thread + reader thread + main thread,
all touching shared mutex-protected state, under a real two-process
network replication run) under ThreadSanitizer. **No data races found.**
This specifically targeted the parts of the code with real shared
mutable state (`AuditLog`'s mutex, `spans_mu`, `pending_mu`), not just
the parts that were already easy to get right.

Also measured real throughput and latency on an actual Release build
(no sanitizers — ASan/UBSan add real overhead, so a performance claim
measured under them isn't honest): **647 calls/sec sustained on a single
sequential connection, p50 1.5ms / p99 2.9ms end-to-end** (5,000 calls
through the full proxy + a Python downstream stub). Important framing
note: this measures the full round trip including the downstream
server's own overhead (a Python subprocess), not Warden's isolated
processing time in isolation, and it's a SEQUENTIAL single-connection
number — this architecture is one proxy process per agent session (like
an MCP server), not a multi-tenant network server, so a "concurrent
req/s across many clients" framing doesn't actually describe this
system and shouldn't be claimed.

## Performance engineering pass: lock-free span store, async quorum, and a real race TSan caught

Three real architecture changes, made because a resume bullet draft
claimed things about the system that weren't true yet ("lock-free fast
path", "asynchronous quorum workers") — rather than write false claims
into any document, built the real thing and measured it.

- **Async quorum dispatch** (`src/quorum.cpp`): `QuorumVerifier::decide()`
  now launches every verifier's `vote()` on its own thread via
  `std::async` and joins via `future::get()`, instead of calling them one
  after another. Total quorum latency is now bounded by the slowest
  verifier, not the sum of all of them — matters most once a real,
  network-bound model-backed verifier is in the mix. Caught and fixed a
  real bug while writing this: the first draft captured the range-for
  loop variable by reference in the async lambda, a classic dangling-
  reference hazard. Fixed by capturing the `shared_ptr<Verifier>` by
  value (just a refcount bump, not a real copy).

- **Lock-free span store** (`src/proxy_main.cpp`): replaced the mutex-
  protected `std::vector<Span>` with an RCU-style atomic snapshot
  (`std::shared_ptr<const std::vector<Span>>`, swapped via
  `std::atomic_load`/`std::atomic_store`). The ingest path (reader
  thread) is the sole writer and builds a whole new immutable vector per
  write; the fast path every `tools/call` goes through (main thread) does
  a single atomic load to get a consistent snapshot, never blocking on a
  lock. This is real lock-free code for the actual concurrency model
  here (single writer, single reader), not a label applied after the
  fact.

- **A real data race, found and fixed.** Running the new concurrent code
  under ThreadSanitizer (not just ASan/UBSan, which can't catch races —
  see the TSan section above) found a genuine bug on the first real
  stress run: `ReplicationServer::listen_fd_` was a plain `int`, written
  by `stop()` on the main thread while concurrently read by
  `accept_loop()` on the accept thread during shutdown — a classic
  shutdown-race. Fixed by making it `std::atomic<int>` with explicit
  `.load()`/`.store()` calls. Fixing it surfaced a second, unrelated
  issue: with `listen_fd_` now a `std::atomic<int>`, the unqualified
  `bind(...)` call became ambiguous with `std::bind` via ADL on the
  atomic's associated `std` namespace — a real compile error, fixed by
  explicitly `::`-qualifying the POSIX socket calls. Re-ran the exact
  scenario that found the race 5 times after the fix, plus the full
  16-scenario benchmark suite and the unit tests, all under TSan: clean.
  Added a dedicated `thread-sanitizer` CI job (`.github/workflows/ci.yml`)
  so this is checked on every push going forward, not just this one
  manual run — including re-running the benchmark and replication demo
  against the TSan-instrumented binary specifically to keep exercising
  the concurrent paths, not just the unit tests.

- **Thread safety of libcurl under concurrent dispatch**: once quorum
  verifiers run concurrently, `AnthropicVerifier` and the replication
  client's `curl_easy_init()` calls could race on libcurl's implicit
  first-use global initialization, which libcurl's own documentation
  says is not safe under concurrent first calls. Added
  `include/warden/curl_init.hpp` / `src/curl_init.cpp`: a single
  `std::call_once`-guarded `curl_global_init()` shared by both call
  sites, closing this before it ever had a chance to manifest as a real
  bug rather than waiting to find it the hard way.

## Delta-CRDT replication (version vectors, not full-state every sync)

`GET /ledger/events` previously always returned this replica's ENTIRE
event set on every call — correct (it's still a valid OR-Set union
source either way), but wasteful: two long-running replicas syncing
repeatedly would re-transmit everything they'd already exchanged, every
time. Implemented real delta-state sync instead:

- `compute_version_vector()` (`include/warden/replication.hpp`): the max
  `lamport_clock` known per origin `replica_id`.
- A peer attaches its own version vector as `?since=replica_id:clock,...`
  on its `GET /ledger/events` request (`encode_version_vector` /
  `decode_version_vector` — plain colon/comma encoding, no percent-
  encoding needed since `replica_id`s are always hex strings).
- The server filters via `delta_since()` before responding: only events
  with a higher clock than what the requester already has FOR THAT
  SPECIFIC ORIGIN REPLICA are sent (an unknown `replica_id` in the
  requester's vector is treated as clock 0 — "send everything from a
  replica I've never seen," which is always safe: worst case redundant
  data, never lost data).

**Verified for real, not just in unit tests**: ran a live proxy, fetched
its full ledger over HTTP (4 events), computed a version vector from
that response the way a real peer would, re-requested with that vector
attached — got back 0 events, confirming the server actually filters
server-side rather than just accepting the parameter. Then triggered one
more tool call (2 more events) and re-requested with the SAME `since`
vector: got back exactly those 2 new events, not the full 6. That's the
actual payoff of "delta," proven over a real HTTP round trip, not
assumed from the unit tests alone (which cover `compute_version_vector`,
`encode`/`decode_version_vector`, and `delta_since` directly — 9 new
tests, `tests/test_replication.cpp`).

## Zero-copy fast-path classification (`include/warden/fastscan.hpp`)

Every line through the proxy's main stdin loop used to get a full
`nlohmann::json::parse()` (real allocation, real parsing work) even
though the result was thrown away for every message that wasn't a
`tools/call` — which is most MCP traffic (initialize, notifications,
`tools/list`, resource reads, pings). Added `might_be_tools_call()`: a
zero-copy substring scan over the raw line (`std::string_view::find`, no
allocation) that skips the full parse entirely for lines that provably
can't be a `tools/call`.

**The safety argument is the actual point of this, not the speedup.** A
naive version of this (searching for the literal substring
`"tools/call"`) would have been a real security bug: valid JSON is
allowed to escape `/` as `\/`, so a conformant MCP client could encode
the method as `"tools\/call"`, and a literal search would silently miss
it — skipping the ENTIRE policy/taint/quorum check for that message and
forwarding it straight through unchecked. Searching for just the `"tools`
prefix instead is provably safe: no valid encoding of `tools/call` can
avoid containing that prefix, so the only failure mode is an occasional
unnecessary full parse (e.g. `tools/list` also matches), never a missed
check. `tests/test_fastscan.cpp` tests the escaped-slash case explicitly
— not a hypothetical, an actual regression test for the exact bug this
design avoids.

## Next steps (not started)

- Automatic periodic sync (background timer thread) instead of only
  on-demand `POST /ledger/sync`.
- Authentication between replication peers before this is ever exposed
  beyond localhost.
- Run the live verifier for real (valid API key) against the benchmark
  suite to get an actual before/after number with a real model in the
  quorum, not just the stub-quorum numbers above.
- Integrate the real AgentDojo / InjecAgent corpora in place of the
  hand-authored fixtures (loader swap, see `scripts/benchmark/README.md`).
