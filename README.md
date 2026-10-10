# Warden

A provenance-aware authorization firewall for agentic AI.

Warden sits as a transparent MCP proxy between an AI agent and its real
tool servers (Gmail, GitHub, Slack, filesystem, shell, etc.). It tracks
the provenance/trust tier of everything a tool call reads, attributes
taint to the specific action it actually justifies (not the whole
session), and routes high-risk actions through an independent,
Byzantine-tolerant quorum of verifiers before letting them execute. Every
decision is recorded in a hash-chained, mergeable audit ledger, so a bad
outcome can be traced back to the exact tool call and untrusted source
that caused it.

**The concrete problem this solves:** an agent that reads untrusted
content (a web page, an email, a Slack message) and can also take real
actions (send email, run code, hit an API) can be hijacked by hidden
instructions in that content — it's the #1 entry on OWASP's LLM Top 10
and the subject of real 2025/2026 incidents (a zero-click CVSS 9.3
indirect injection in M365 Copilot; a state-sponsored group hijacking
Claude Code sessions for autonomous cyber-espionage). See
[DESIGN.md](./DESIGN.md) for the full threat model, prior-art gap
analysis, and architecture.

## Status

M0–M5 implemented and tested: taint tracking, policy engine, quorum
verifier (including a real Claude-backed verifier), hash-chained audit
ledger with an attribution tool, and real network replication between
live Warden instances (two separate processes syncing over actual HTTP,
not just an in-memory merge — see `scripts/replication_demo.py`). CI
runs the full suite — unit tests under ASan/UBSan, the attack demo, the
benchmark, and the live two-process replication test — on every push.
See [NOTES.md](./NOTES.md) for the actual measured results at each
stage, including a false-positive regression and a real UB bug in a
vendored dependency that got found and fixed, not just the clean final
numbers.

Benchmarked on a hand-authored fixture set mirroring AgentDojo's domain
split (banking/Slack/workspace/travel): **100% → 0% attack success rate,
0% false-positive rate**, with a real model-backed verifier available
(not yet run against a live corpus — see NOTES.md).

Still open: peer authentication/discovery for replication, automatic
(vs. on-demand) sync, and a live benchmark run against a real
AgentDojo/InjecAgent corpus with a paid API key — see NOTES.md's "Next
steps" for the honest remaining list.

## Quickstart

Requires CMake 3.20+, a C++20 compiler, and libcurl (present by default
on macOS; on Ubuntu/Debian: `sudo apt-get install libcurl4-openssl-dev`).

```bash
git clone https://github.com/aadihuria/warden.git
cd warden
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/warden_tests          # 66 unit tests, no network/API key needed
```

### Try it against a toy poisoned-page attack

```bash
python3 scripts/demo_driver.py
```

This runs a real end-to-end scenario: an agent reads a fake "poisoned"
web page containing a hidden instruction to exfiltrate data via email.
With Warden in front, the email is blocked; the same sequence against
the bare downstream server with no Warden succeeds. See
`scripts/fake_mcp_server.py` for the toy server and
`scripts/demo.warden.json` for the config shape.

### Point it at a real MCP server

Warden wraps a real downstream MCP server transparently — point your MCP
client at Warden instead of the real server, and give Warden a config
telling it what to wrap and how to classify each tool:

```json
{
  "downstream_command": ["node", "path/to/real-mcp-server.js"],
  "audit_log": "warden-audit.log",
  "trusted_destinations": ["@yourcompany.com", "#"],
  "tools": {
    "fetch_url":   { "ingests_untrusted": true, "risk_class": "READ_ONLY" },
    "send_email":  { "risk_class": "EXTERNAL_COMM" },
    "delete_file": { "risk_class": "IRREVERSIBLE_WRITE" }
  }
}
```

```bash
./build/warden-proxy path/to/your-config.json
```

Set `ANTHROPIC_API_KEY` in the environment to upgrade the quorum's third
verifier from a free deterministic stub to a real Claude-backed verifier
automatically — no config change needed (see NOTES.md for cost notes:
this means a real, billed API call per quorum-escalated action).

### Install system-wide

```bash
cmake --install build --prefix /usr/local
```

### Run the benchmark / regression suite

```bash
python3 scripts/benchmark/runner.py      # attack success rate + false-positive rate
python3 scripts/proxy_edge_cases.py      # malformed input / crash resistance
```

Both are free and deterministic (no API key needed) and are what CI runs
on every push — see `.github/workflows/ci.yml`.

### Inspect and verify the audit ledger

```bash
python3 scripts/ledger/attribute.py warden-audit.log
```

Independently re-verifies the entire hash chain and, for any blocked or
escalated decision, walks back to the exact tool call that supplied the
taint that caused it.

### Run two Warden instances and watch them sync for real

```bash
python3 scripts/replication_demo.py
```

Starts two real, separate `warden-proxy` processes on different ports,
each recording a decision independently, triggers a real HTTP sync
between them, and verifies both converge to the identical, hash-chain-
verified combined log. To do this yourself: add a `"replication"` block
to a config —

```json
"replication": { "listen_port": 7001, "peers": ["http://127.0.0.1:7002"] }
```

— then `curl -X POST http://127.0.0.1:7001/ledger/sync` to pull in any
new events from configured peers.

## Repo layout

- `include/warden/`, `src/` — the core library: trust lattice & taint
  attribution, policy engine, quorum verifier (+ a real Claude-backed
  verifier), CRDT audit ledger, and the HTTP replication layer that syncs
  ledgers between live instances.
- `src/proxy_main.cpp` — the MCP stdio proxy itself.
- `tests/` — 66 unit tests, run under ASan/UBSan.
- `scripts/benchmark/` — the attack-success-rate / false-positive
  measurement harness and fixture scenarios.
- `scripts/ledger/` — audit log verification and attribution tooling.
- `DESIGN.md` — full architecture, threat model, and gap analysis against
  prior art.
- `NOTES.md` — the actual build log: what's implemented, what's
  simplified and why, real bugs found and fixed, and measured results at
  each milestone (not just the final numbers).

## License

Apache-2.0 (see [LICENSE](./LICENSE)).
