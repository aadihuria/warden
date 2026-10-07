# Warden: A Provenance-Aware Authorization Firewall for Agentic AI

**Status:** Design doc, ready for implementation
**Author context:** Aadi Huria (systems + distributed systems + agentic AI background — see "Fit" section at the end)
**Intended reader:** An AI coding agent (or engineer) implementing this project end-to-end
**Target outcome:** A working, benchmarked, open-source system that solves a real, currently-unsolved production problem in agentic AI security, built to a standard that survives an OpenAI/Anthropic/top-tier systems interview.

---

## 0. TL;DR

LLM agents that can both **read untrusted content** and **take real-world actions** (send email, run code, move money, push to prod) are being hijacked in production right now via prompt injection, and the industry has no adequate answer. Existing defenses either (a) bind *identity* to actions (aiAuthZ-style off-host authorization) without asking whether the *reasoning behind the action* was contaminated by untrusted input, or (b) architecturally separate "thinking" from "acting" (Parallax-style privilege separation) without solving how *multiple* agents cross-check each other or how you attribute a bad outcome to the agent/step that caused it once several agents touched the task.

**Warden** closes this gap with four components that compose:

1. **Taint-tracking interceptor** — every token of context an agent sees is labeled with a provenance/trust tier at ingestion time; taint propagates through the agent's reasoning trace so that, at the moment of a tool call, Warden knows *which untrusted sources influenced this specific action*.
2. **Capability derivation engine** — instead of static RBAC, the privilege granted to an action is computed live from `(agent identity, requested tool+args, taint lineage, action risk class)`. A "send email" action whose justification traces back to an untrusted inbound email is capped to a low-privilege capability regardless of the agent's normal permissions.
3. **Quorum verifier** — for actions above a configurable risk threshold, Warden doesn't just check a policy — it fans the action out to N independent verifier agents (different model, different prompt, no shared context) and requires a Byzantine-tolerant quorum (e.g., 2-of-3) of independent, evidence-grounded approvals before execution, using the same evidence-cross-verification pattern proven to work at Amazon Ads (94% requirement-validation accuracy) and the same fault-tolerant quorum math as Raft.
4. **Tamper-evident, CRDT-based audit ledger** — every decision (allowed, denied, escalated) is written to a hash-chained, merge-safe distributed log so that when a multi-agent system produces a bad outcome, you can attribute it to the exact agent, tool call, and taint lineage that caused it — solving the "attribution problem" that the 2026 agent-reliability literature calls out as unsolved.

Warden ships as an **MCP-transparent proxy**: any agent framework that speaks Model Context Protocol (Claude, ChatGPT agents, custom LangChain/LangGraph/CrewAI stacks) points its tool calls through Warden with no code changes to the agent itself. This is what makes it *useful to other people*, not just a personal resume project — it's a drop-in security layer for the exact problem every team shipping agents in 2026 has and cannot solve today.

---

## 1. The problem, with receipts (why this is real, not speculative)

This is not a hypothetical AI-safety thought experiment. As of 2026:

- **Prompt injection is #1 on the OWASP LLM Top 10**, and both OpenAI and independent researchers now describe it as an unsolved, frontier problem rather than a bug awaiting a patch. OWASP's 2026 report puts prompt injection attack volume up **340% year-over-year**, with **indirect injection (hidden in email/documents/web pages the agent reads) now over 55% of incidents** and 20–30% higher success rates than direct attempts.
- **CVE-2025-32711 (Microsoft 365 Copilot, CVSS 9.3):** a zero-click indirect prompt injection via a single crafted email. Copilot ingested the email during routine summarization, followed hidden instructions, and exfiltrated data from OneDrive/SharePoint/Teams through a trusted Microsoft domain. No user interaction required.
- **GTG-1002 (disclosed by Anthropic, Sept 2025):** a state-sponsored group hijacked Claude Code agent sessions to run autonomous cyber-espionage against ~30 defense/energy/tech targets. The AI executed 80–90% of tactical operations independently, at request rates impossible for a human operator — the first documented largely-autonomous cyberattack at scale.
- **LiteLLM PyPI backdoor (March 2026):** a compromised package sat live for 3 hours and got ~47,000 downloads. LiteLLM is the LLM gateway underneath CrewAI, DSPy, Microsoft GraphRAG, and dozens of other agent frameworks — a single supply-chain compromise point for the agentic ecosystem.
- **Five Eyes joint guidance (May 2026):** CISA/NSA + UK/CA/AU/NZ counterparts explicitly name prompt injection as a core agent-manipulation vector and state that **no single safeguard is sufficient** — i.e., defense-in-depth, not a silver bullet, is the only credible framing. This is the framing Warden adopts.
- **On the reliability side (separate from adversarial attack):** multi-agent LLM systems fail in production at rates of **41–86.7%** due to coordination breakdowns. The 2026 literature specifically names three failure modes as unsolved: **authorization drift** (an agent's effective privilege drifts from its intended scope over a session), **compounding errors** (small mistakes propagate and amplify across agent handoffs), and **attribution** (once a multi-agent pipeline produces a bad outcome, nobody can cheaply determine which agent/step caused it).

**The core structural issue** (the "lethal trifecta," per Simon Willison and formalized in the Parallax paper): an agent becomes dangerous exactly when it has (1) exposure to untrusted content, (2) access to private/sensitive data or systems, and (3) a channel to take external action or communicate. Almost every useful agent — a coding agent that reads GitHub issues and pushes commits, a support agent that reads customer emails and issues refunds, a research agent that reads the web and files reports — has all three by design. You cannot remove any leg of the trifecta without destroying the agent's usefulness, so the only lever left is: **verify, at the moment of action, that the action's justification isn't contaminated by the untrusted leg, and don't let one contaminated agent's decision go unchecked.**

---

## 2. Gap analysis: why existing approaches don't close this

Two credible pieces of prior art exist and Warden should be explicitly positioned relative to both — this is what turns the project from "yet another agent guardrail" into a defensible, citable contribution.

**aiAuthZ (off-host, identity-bound authorization for AI agents).** Binds authorization tokens cryptographically to agent identity and validates off-host so a compromised agent can't forge or exfiltrate credentials. This is necessary but insufficient: it answers *"is this agent who it claims to be, and is it allowed to call this tool at all?"* — not *"was this specific invocation's reasoning contaminated by untrusted input?"* A legitimately-identified, fully-authorized agent that has been prompt-injected sails straight through identity-bound auth, because the exploit isn't credential theft — it's hijacking the *intent* of an agent using its own legitimate credentials. Its authors also flag centralized-bottleneck risk at scale, no compromise-detection mechanism, and no cross-domain federation — open problems Warden should not try to re-solve, but should design around (Warden's quorum layer is decentralized/replicated by construction, which sidesteps the bottleneck critique).

**Parallax (reasoning/acting privilege separation).** Architecturally separates the "thinking" component from the "acting" component with an information-flow-controlled validation layer between them, drawing on Bell–LaPadula and privilege-separation (Provos 2003). This is the right shape of idea, but it is single-agent and coarse-grained: it doesn't specify *how fine the taint labels are*, doesn't handle *multi-step iterative reasoning* well (acknowledged as an open problem in the paper), and says nothing about what happens when **multiple agents** collaborate — there's no cross-agent verification and no attribution mechanism when a multi-agent pipeline is the thing that goes wrong. It also leaves "optimal granularity for action approval" explicitly open.

**Warden's contribution is the synthesis these two don't attempt together:**
- Fine-grained, per-token/per-context-chunk taint propagation (goes further than Parallax's binary think/act split) feeding into
- Capability derivation instead of static identity-based ACLs (goes further than aiAuthZ's identity-only model), gated by
- A decentralized, Byzantine-tolerant multi-agent quorum for high-risk actions (neither paper addresses cross-agent verification), all recorded in
- A CRDT-based, merge-safe, hash-chained audit log purpose-built for **attribution** across distributed multi-agent systems (the specific unsolved problem named in the 2026 reliability literature, not really addressed by either security paper since they're both single-agent-focused).

This is the honest scope: Warden does not claim to "solve" prompt injection (nobody credibly can, per Five Eyes' own guidance) — it claims to make the *blast radius of a successful injection bounded, attributable, and cheap to contain*, which is the realistic, industry-accepted framing for 2026 and is exactly why reviewers at a frontier lab will find it credible rather than naive.

---

## 3. System overview

```
                    ┌─────────────────────────────────────────────────┐
                    │                  Agent runtime                   │
                    │   (Claude / GPT agent / LangGraph / CrewAI /...)  │
                    └───────────────────────┬───────────────────────────┘
                                             │  MCP tool-call request
                                             ▼
        ┌───────────────────────────────────────────────────────────────┐
        │                         WARDEN PROXY                          │
        │                                                                 │
        │  ┌───────────────┐   ┌────────────────────┐   ┌─────────────┐ │
        │  │ Taint Tracker │──▶│ Capability Deriver  │──▶│ Risk Router │ │
        │  └───────────────┘   └────────────────────┘   └──────┬──────┘ │
        │                                                        │        │
        │                            low risk ◀───────┬──────────┘        │
        │                                              │  high risk       │
        │                                              ▼                  │
        │                                    ┌────────────────────┐       │
        │                                    │   Quorum Verifier   │       │
        │                                    │ (N independent      │       │
        │                                    │  verifier agents,   │       │
        │                                    │  Raft-style vote)   │       │
        │                                    └──────────┬──────────┘       │
        │                                               │                  │
        │                                               ▼                  │
        │                                  allow / deny / escalate-human   │
        │                                               │                  │
        └───────────────────────────────────────────────┼──────────────────┘
                                                          ▼
                                          ┌───────────────────────────┐
                                          │  CRDT Audit Ledger (Concord- │
                                          │  style: hash-chained,       │
                                          │  merge-safe, replicated)    │
                                          └───────────────────────────┘
                                                          │
                                                          ▼
                                              Real tool / API execution
```

Warden sits as a **transparent MCP proxy** between the agent's tool-calling layer and the actual MCP servers (filesystem, GitHub, Slack, email, shell, DB, etc.). This is the integration point that makes adoption zero-friction: point `MCP_SERVER_URL` at Warden instead of the real server; Warden forwards to the real server after a decision.

---

## 4. Component design

### 4.1 Taint Tracker

**Goal:** know, for every piece of text/data currently in an agent's context, where it came from and how trusted it is — and propagate that through summarization/paraphrase so it survives the LLM's own reasoning step.

**Trust lattice** (four tiers, ordered low→high trust):
```
UNTRUSTED_EXTERNAL   (web pages, inbound emails, third-party API responses, tool outputs from
                       sources the agent doesn't control, retrieved RAG documents)
UNTRUSTED_INTERNAL   (other agents' outputs in a multi-agent pipeline, unless those agents
                       are themselves fully verified — internal ≠ trusted)
OPERATOR             (the deploying org's own config, system prompt, policy files)
PRINCIPAL            (the authenticated human user's direct, current-turn input)
```
This is a lattice, not a total order tie-break: taint **only flows downward** (a blended context chunk inherits the *minimum* trust tier of its inputs — same join-semilattice structure as an information-flow label, à la Bell–LaPadula's "no read up / no write down," which is the same primitive Parallax gestures at but doesn't formally specify).

**Tagging at ingestion.** Every MCP tool response, every RAG-retrieved chunk, every inbound message gets wrapped with a provenance envelope before it enters the agent's context window:
```json
{
  "content": "...",
  "source_id": "gmail:msg:1839...",
  "trust_tier": "UNTRUSTED_EXTERNAL",
  "ingested_at": "...",
  "content_hash": "sha256:...",
  "span_id": "uuid"   // stable id used for propagation tracking
}
```

**Propagation through reasoning.** The hard part, and the part neither aiAuthZ nor Parallax specify concretely: LLMs paraphrase, summarize, and recombine tainted content, so you can't just grep the final tool-call arguments for a source string. Warden's approach — a lightweight, practical approximation, not full formal dataflow analysis (which is intractable over free-text LLM reasoning, and the Parallax paper itself flags formal IFC verification as an open problem):
1. **Structured scratchpad requirement.** Warden requires (via system-prompt injection it controls, invisible to the agent's own prompt) that the agent's reasoning trace cite `span_id`s when it uses information from context. Modern tool-calling models (Claude, GPT-5-class) already do citation-style grounding well when asked; this reuses that capability rather than inventing new model behavior.
2. **Fallback taint inference when citations are absent/unreliable:** run a cheap classifier (small model or embedding-similarity check) comparing the tool-call arguments against each tainted span in context; if similarity exceeds a threshold, treat that span as a taint source for this action. This is the same "evidence-grounding cross-verification" pattern already proven in production (Amazon Ads agent: cross-verifies proposed feedback against source/history, only surfaces grounded comments) — Warden generalizes that exact technique from "is this comment grounded" to "is this action's justification grounded, and in what trust tier."
3. **Conservative default:** if taint lineage can't be established with confidence, the action is treated as tainted by the lowest tier present anywhere in the current context window. Fail closed, not open — this is a security system.

**Output of this stage:** every tool-call request arrives at the next stage annotated with a `taint_lineage: {min_trust_tier, contributing_span_ids[], confidence}`.

### 4.2 Capability Derivation Engine

Replaces static RBAC/ACL checks with a computed capability per call:

```
capability = derive(
    agent_identity,        # from aiAuthZ-style off-host identity binding — Warden doesn't
                            # reinvent this, it consumes it as an input
    tool, args,
    taint_lineage,
    action_risk_class       # static per-tool classification: READ_ONLY / REVERSIBLE_WRITE /
                            # IRREVERSIBLE_WRITE / EXTERNAL_COMM / FINANCIAL / CODE_EXEC
)
```

Policy is expressed as a small declarative DSL (think OPA/Rego-lite, but taint-aware — this is a genuinely novel piece since Rego has no concept of provenance taint):

```rego
# example policy
deny[msg] {
  input.action_risk_class == "EXTERNAL_COMM"
  input.taint_lineage.min_trust_tier == "UNTRUSTED_EXTERNAL"
  input.taint_lineage.confidence > 0.6
  msg := "external communication justified by untrusted external content — requires quorum"
}

escalate_to_quorum[msg] {
  input.action_risk_class == "IRREVERSIBLE_WRITE"
  input.taint_lineage.min_trust_tier != "PRINCIPAL"
}

allow {
  input.action_risk_class == "READ_ONLY"
}
```

This alone (taint-aware policy, not identity-only policy) is the concrete technical delta over aiAuthZ, and it's implementable and testable independent of the harder quorum piece — good for an early milestone.

### 4.3 Quorum Verifier (the distributed-systems core — this is where Concord experience transfers directly)

For actions the policy engine escalates, Warden doesn't ask one model "is this ok?" (an injected agent can just as easily fool a single verifier). It fans out to **N independently-configured verifier agents** and requires a quorum:

- Different model or at minimum different system prompt/context per verifier (no shared contamination surface).
- Each verifier receives *only* the proposed action + the cited evidence spans + their trust tiers — **not** the full untrusted context — so a verifier can't itself be re-injected by the same payload that fooled the primary agent. This is the key design property: **verifiers are context-isolated from the untrusted source that triggered the escalation.**
- Verifiers vote `APPROVE` / `DENY` / `ABSTAIN` with a written justification (reuses the evidence-grounded-comment pattern again).
- **Quorum rule:** Byzantine-tolerant `f`-fault threshold — with N=3, require 2 approvals with zero denies, any single deny escalates to human, matching the same quorum math used in Raft leader election / commit rules, which is directly reusable design experience from a from-scratch Raft implementation.
- **Latency budget:** this only runs for the (empirically rare, per the risk classification) high-risk action tier, so the added latency is acceptable — this needs to be validated empirically in benchmarking (Milestone M4).

This directly answers the "no single safeguard is enough" Five Eyes guidance with an actual mechanism, and it's the piece of the project most directly reusing distributed-systems chops (quorum/consensus) in a domain (AI safety) where almost nobody with that systems background is currently working — which is exactly the rare intersection that gets noticed in interviews.

### 4.4 CRDT Audit Ledger (attribution — the piece the 2026 literature says is unsolved)

Every decision — allow, deny, escalate, quorum vote, human override — is written as an event to an append-only, hash-chained log, replicated using the same CRDT approach as the Concord project (OR-Set / RGA-sequence semantics for merge-safety across replicated Warden proxy instances, so decisions recorded during a network partition merge deterministically once healed — directly reusable design from LWW-Register/OR-Set/RGA work):

```
Event {
  event_id: UUID,
  prev_hash: sha256,                # hash-chain for tamper evidence
  timestamp,
  agent_identity,
  tool, args_hash,
  taint_lineage,                    # full span_id chain, not just the summary
  decision: Allow | Deny | Escalated,
  quorum_votes: [ {verifier_id, vote, justification} ],
  outcome_hash: sha256              # filled in post-hoc if the action's real-world
                                     # effect is later known (e.g. "email sent",
                                     # "PR merged and later reverted")
}
```

**Why this solves attribution, concretely:** when a multi-agent pipeline produces a bad outcome, you replay the hash-chain backward from the outcome event through `taint_lineage.contributing_span_ids` to find the exact agent, tool call, and upstream data source responsible — turning "which of our 6 agents caused this" (today, a manual log-spelunking exercise per the reliability literature) into a graph traversal over a structured, replicated ledger. This is the same "provenance-verified constraints" idea already shipped in production (the Amazon Ads tribal-knowledge MCP server reduced knowledge-base noise 58% via provenance verification) generalized from "is this fact grounded" to "is this *action* attributable."

---

## 5. What to build, in order (milestones for the implementing agent)

**M0 — Core taint + policy engine (single agent, no quorum, no CRDT).**
- Rust core crate: provenance envelope types, trust lattice, taint propagation via citation-parsing + embedding-similarity fallback.
- MCP proxy (Rust, tokio + tonic/gRPC or plain JSON-RPC over stdio/HTTP matching MCP spec) that wraps a real MCP server transparently.
- Taint-aware policy DSL + evaluator (small hand-rolled interpreter is fine; don't over-engineer with a full Rego VM initially).
- Deliverable: point Claude (via MCP) at a filesystem + web-fetch MCP server through Warden; demonstrate a crafted "poisoned webpage" causes a `deny`/`escalate` that an unprotected setup would have allowed.

**M1 — Benchmark against real injection corpora.**
- Integrate with published agentic-injection benchmarks (AgentDojo, InjecAgent — verify current names/availability at implementation time) to get a defensible, comparable attack-success-rate number, not just hand-crafted demos.
- Metrics: attack success rate with/without Warden, false-positive rate (legitimate actions wrongly blocked), added latency (p50/p99).

**M2 — Capability derivation + richer risk classification.**
- Expand action_risk_class taxonomy per real MCP server catalog (GitHub, Slack, email, shell, Stripe-like payment stub).
- Policy authoring ergonomics: a small test harness so policy authors can unit-test policies against synthetic taint scenarios (property-based tests, matching the Concord CRDT-invariant testing discipline — this is a strong, resume-consistent engineering signal: bring the same "11 CRDT invariants + fault injection" rigor to policy correctness here).

**M3 — Quorum verifier.**
- Implement the N-verifier fan-out + vote aggregation as its own service; reuse gRPC patterns from Concord.
- Context-isolation guarantee must be testable: write an explicit test that proves a verifier given only the redacted evidence bundle cannot access the full untrusted payload (i.e., prove the isolation property, don't just assert it).
- Byzantine-tolerant quorum logic with configurable N/f, unit-tested the way Raft leader election was fault-injection-tested in Concord.

**M4 — CRDT audit ledger + attribution tooling.**
- Replicated, hash-chained event log using OR-Set/RGA merge semantics (direct reuse of Concord's CRDT layer, PyO3/gRPC bindings already exist in that codebase and can be adapted).
- Build a small attribution CLI/dashboard: given a bad-outcome event_id, walk `contributing_span_ids` backward and print the responsible agent/tool/source chain.
- Fault-injection test: partition two Warden replicas, generate decisions on both sides, heal partition, assert deterministic merge with no lost/duplicated audit events (same test discipline as Concord's network-partition tests).

**M5 — Packaging, docs, and real adoption surface.**
- Ship as an installable MCP proxy (`npx warden-mcp` / `pip install warden-mcp` / prebuilt binary) — the whole point is other teams can drop it in front of their existing MCP servers with a config file, not a research prototype only you can run.
- Write up results (attack-success-rate reduction, latency overhead, false-positive rate) as a short technical report/blog post with the benchmark methodology public — this is what makes it citable and gives you a concrete artifact to walk through in interviews.

---

## 6. Evaluation plan (what "done" looks like, quantitatively)

| Metric | Target | Why it matters |
|---|---|---|
| Attack success rate on injection benchmark, with Warden vs. without | ≥70% relative reduction | The headline number; must be measured against a real published benchmark, not self-authored attacks only, to be credible |
| False-positive rate (legitimate actions blocked/escalated) | <5% at the chosen policy defaults | A system nobody can use because it blocks everything isn't a contribution |
| Added p50 / p99 latency for low-risk (non-quorum) actions | <20ms / <50ms | Must be usable in real agent loops |
| Added latency for quorum-escalated actions | Reported, not necessarily minimized — document the tradeoff explicitly | Honesty about the cost of the safety mechanism is itself a signal of engineering maturity |
| Audit ledger: partition-heal determinism | 100% (property-based test, N runs) | This is a correctness property, not a benchmark — it must be proven, not estimated |
| Attribution correctness on synthetic multi-agent failure scenarios | Correctly identifies root-cause agent/span in ≥95% of injected synthetic failures | Directly validates the "attribution" claim against the literature's named unsolved problem |

---

## 7. Threat model and explicit non-goals

**In scope:** indirect prompt injection via tool outputs, RAG documents, emails, web content; multi-agent coordination failures that cause misattributed/unbounded blast radius; supply-chain-adjacent risk in the sense that Warden itself must be auditable (open-source, small trusted-computing-base core in Rust).

**Explicitly out of scope (state this plainly in the doc/paper — reviewers respect a scoped claim far more than an oversold one):**
- Warden does not detect or prevent model weight-level backdoors or training-time poisoning.
- Warden does not replace sandboxing for code execution (it decides *whether* a code-exec action is authorized; the actual sandbox is a separate, complementary control).
- Warden does not claim to stop a sufficiently novel injection that also compromises *all N* independently-configured verifiers simultaneously — it reduces this to a probability that can be tuned via N and verifier diversity, and that assumption should be stated and, if possible, empirically stress-tested in M1–M3 rather than asserted.
- Human-in-the-loop escalation is a fallback path, not eliminated — per aiAuthZ's own acknowledged gap, and per Five Eyes' "no single safeguard" framing, this project should not pretend full autonomy is safe for the highest-risk tier.

---

## 8. Why this project, specifically, is the right one for Aadi Huria (fit rationale — keep in mind while implementing, and reuse this framing in interview prep)

This isn't a generic "add guardrails to an LLM" project — it's assembled almost entirely from things already proven out on the resume, recombined into a genuinely new synthesis:

- **Concord** (hand-rolled Raft + CRDT layer, 202k ops/sec, fault-injection-tested) → directly supplies the quorum-verifier consensus logic and the CRDT audit ledger. This is not a toy reuse — it's the same rigor (property-based testing across invariants, network-partition fault injection) applied to a security-critical log instead of a generic KV store.
- **Amazon Ads three-agent system** (evidence-grounded, provenance-verified comments; multi-source RAG lifting accuracy 53%→94%; TypeScript MCP server for provenance-verified constraints) → directly supplies the taint-tracking/evidence-grounding design and the choice of MCP as the integration surface. Warden generalizes a pattern already shipped and measured in production, which is a much stronger interview story than an unproven idea.
- **RAG, LLM evaluation, agentic/multi-agent systems, vector DBs, MCP** (skills list) → exactly the toolset the taint tracker and capability engine need.
- **Rust, gRPC/Protobuf, Kubernetes, AWS** → exactly the toolset for the proxy, quorum service, and ledger.

The interview narrative this produces is unusually strong and hard to fake: *"I noticed that the two published defenses for agentic AI security each solve half the problem — identity-bound auth doesn't check whether reasoning was contaminated, and think/act separation doesn't handle multi-agent attribution — so I built the missing piece using the same consensus and provenance-verification techniques I'd already shipped in a from-scratch Raft/CRDT store and a production evidence-grounding agent, and I benchmarked it against a real injection corpus to get an actual attack-success-rate reduction number."* That is a systems-plus-safety story, told with real numbers, that very few new-grad or intern candidates can tell — which is precisely what a place like OpenAI or Anthropic is filtering for.

---

## 9. Open questions to resolve during implementation (don't guess — verify empirically or ask)

1. Confirm current availability/API of AgentDojo / InjecAgent (or successor benchmarks) at implementation time — the literature landscape moves fast; re-verify rather than trusting this doc's citations as still-current.
2. Decide verifier model diversity strategy concretely (different vendor models vs. same vendor/different prompt) — this materially affects the independence assumption underpinning the quorum's security guarantee; document the tradeoff rather than picking silently.
3. Decide MCP spec version compatibility target and re-check the current spec before building the proxy, since MCP itself is an evolving standard.
4. Decide licensing (Apache-2.0 recommended for adoption) before any public release, since usefulness-to-others is a stated project goal.
