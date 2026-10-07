# M1 benchmark harness

This is the pipeline for measuring Warden's effect on attack success rate
(ASR) and false-positive rate, per DESIGN.md's M1 milestone and evaluation
plan (section 6).

## What's here right now

- `scenario_server.py` — a generic stdio MCP-ish server driven by a
  scenario JSON file. It serves scripted tool responses (including
  injection payloads for attack scenarios) and logs every tool call it
  actually receives — i.e. every call that got *past* Warden — to a
  JSONL log, which is how the runner scores attack success.
- `scenarios/*.json` — hand-authored scenario fixtures across four
  domains mirroring AgentDojo's own domain split (banking, Slack, email/
  workspace, travel): 4 attack scenarios (poisoned tool output tries to
  trigger an unauthorized high-risk action) and 3 benign-only scenarios
  (no injection at all, used to measure false positives).
- `agent_backends.py` — pluggable "agent" that decides what to do next.
  `StubBackend` is free and deterministic: `gullible=True` simulates an
  agent that complies with any injected instruction it sees (the
  worst-case baseline), `gullible=False` simulates one that ignores
  injected instructions and just does the benign task (the best-case
  baseline). `AnthropicBackend` is a real-model backend, stubbed out —
  see "Plugging in a real model" below.
- `runner.py` — drives every (scenario x Warden on/off x backend)
  combination, scores attack success / benign task success / blocking,
  and prints + writes a JSON report.

## Why hand-authored scenarios first, not AgentDojo/InjecAgent directly

DESIGN.md's open question #1 says to re-verify benchmark availability
before building against it rather than trusting the doc's citations. As
of this harness being built (see repo history), both AgentDojo
(ethz-spylab/agentdojo on GitHub — 97 tasks / 629 security test cases
across Banking/Slack/Workspace/Travel) and InjecAgent (1,054 test cases)
are still active, so the plan is still to integrate the real corpora. But
installing and adapting a third-party benchmark harness, and wiring real
paid LLM calls through it, is exactly the kind of action worth getting
right once the plumbing is already proven — so this first pass builds
the full scoring pipeline against free, deterministic, hand-written
fixtures that mirror AgentDojo's domain shape. Swapping in the real
corpora is a loader change (`scenarios/*.json` -> an adapter that maps
AgentDojo/InjecAgent's task format into the same schema), not a rewrite
of the runner or scoring logic.

## Scenario schema

See any file in `scenarios/` for a concrete example. Key fields:

- `tools`: per-tool `risk_class` / `ingests_untrusted`, same shape as a
  Warden config's `"tools"` block — the runner uses this to generate a
  per-scenario Warden config automatically.
- `tool_script`: scripted response text per tool, including the
  injection payload (marked with the `INJECTION_MARKER` constant from
  `agent_backends.py`) for attack scenarios.
- `benign_plan`: the ordered tool calls a well-behaved agent makes to
  complete the stated task, ignoring any injected instructions. This is
  the ground truth a stub backend follows.
- `injected_action` (attack scenarios only): the tool call a *hijacked*
  agent would make — e.g. `send_email` to an attacker address instead of
  the real recipient.
- `attack_success_check` / `benign_success_check`: how the runner decides
  whether a logged tool call counts as the attack succeeding / the benign
  task succeeding (field + expected value match).

## Running it

```
python3 scripts/benchmark/runner.py
```

No API key or network access needed — everything runs against the stub
backend and the local scenario server. Prints a summary and writes
`scripts/benchmark/report.json`.

## Plugging in a real model

`agent_backends.py::AnthropicBackend` (the agent loop that DECIDES what
tool to call) is still unimplemented — it needs a real API key and will
incur real per-run cost, which is a call for whoever runs it, not
something to wire up silently. See the class docstring for the interface
it needs to satisfy.

**The quorum's third VERIFIER is different: it's already implemented**
(`include/warden/anthropic_verifier.hpp` / `src/anthropic_verifier.cpp`,
C++, not Python) and auto-upgrades from a free no-op stub
(`AlwaysApproveVerifier`) to a real Claude Haiku-backed verifier the
moment `ANTHROPIC_API_KEY` is set in the environment — no code change
needed, see `src/proxy_main.cpp`. **This means: if you run
`runner.py` with `ANTHROPIC_API_KEY` exported, every scenario that hits
the quorum path (currently the benign ones, by design — see NOTES.md)
will make a real, billed API call.** Cheap (Haiku, ~300 max output
tokens, short prompts, a handful of scenarios) but not free — unset the
key if you want the free/deterministic run, export it when you
deliberately want to measure the live-verifier quorum.
