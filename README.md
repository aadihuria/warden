# Warden

A provenance-aware authorization firewall for agentic AI.

Warden sits as a transparent MCP proxy between an AI agent and its tool
servers (Gmail, GitHub, Slack, filesystem, shell, etc.). It tracks the
provenance/trust tier of everything in an agent's context, derives a
per-call capability instead of relying on static identity-based ACLs, and
routes high-risk actions through an independent, Byzantine-tolerant quorum
of verifier agents before execution. Every decision is recorded in a
replicated, hash-chained CRDT audit ledger so that a bad outcome in a
multi-agent pipeline can be attributed back to the exact agent, tool call,
and untrusted source responsible.

See [DESIGN.md](./DESIGN.md) for the full architecture, threat model,
and build plan.

## Status

Design complete. Implementation in progress (see milestones M0–M5 in
DESIGN.md).

## License

Apache-2.0 (see [LICENSE](./LICENSE)).
