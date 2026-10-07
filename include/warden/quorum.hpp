#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "warden/policy.hpp"
#include "warden/taint.hpp"

namespace warden {

enum class Vote { Approve, Deny, Abstain };
std::string to_string(Vote v);

// A bounded excerpt of a span that contributed taint to the action under
// review — bounded so a future LLM-backed verifier isn't handed an
// unbounded amount of (possibly adversarial) text to reason over.
struct EvidenceExcerpt {
    std::string span_id;
    TrustTier trust_tier;
    std::string excerpt;
};

struct VerificationRequest {
    std::string tool_name;
    ActionRiskClass risk_class;
    // Top-level string arguments of the proposed action, e.g. {"to",
    // "attacker@evil.example"}. Deliberately NOT the full nested
    // argument JSON — keeps the core library free of a JSON dependency
    // and keeps verifiers working off simple, inspectable fields.
    std::vector<std::pair<std::string, std::string>> argument_fields;
    std::vector<EvidenceExcerpt> evidence;
    double confidence = 0.0;
};

struct VerifierVote {
    std::string verifier_id;
    Vote vote;
    std::string justification;
};

// A Verifier only ever returns a vote. See DESIGN.md section 4.3: by
// construction it has no tool-execution capability, so a verifier whose
// reasoning gets hijacked by adversarial content in the evidence can only
// cast a bad vote, never take a real action.
class Verifier {
public:
    virtual ~Verifier() = default;
    virtual VerifierVote vote(const VerificationRequest& req) const = 0;
    virtual std::string id() const = 0;
};

enum class QuorumOutcome {
    Allow,
    Deny,
    EscalateToHuman,  // no verifier capable of giving a confident answer
                        // either way (all abstained, or verifiers split
                        // without any deny) — M3 has no human-escalation
                        // channel wired up yet, so the caller currently
                        // treats this the same as Deny. See NOTES.md.
};

std::string to_string(QuorumOutcome o);

struct QuorumResult {
    QuorumOutcome outcome;
    std::string reason;
    std::vector<VerifierVote> votes;
};

// Byzantine-tolerant-in-spirit quorum: ANY single Deny blocks the action
// (fail closed on disagreement — DESIGN.md section 4.3's "any single deny
// escalates to human"), Allow requires at least `required_approvals`
// Approve votes with zero Denies, anything else (not enough signal) also
// escalates rather than defaulting to Allow.
class QuorumVerifier {
public:
    QuorumVerifier(std::vector<std::shared_ptr<Verifier>> verifiers, int required_approvals = 2);

    QuorumResult decide(const VerificationRequest& req) const;

private:
    std::vector<std::shared_ptr<Verifier>> verifiers_;
    int required_approvals_;
};

}  // namespace warden
