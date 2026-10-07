#include "warden/quorum.hpp"

namespace warden {

std::string to_string(Vote v) {
    switch (v) {
        case Vote::Approve: return "APPROVE";
        case Vote::Deny: return "DENY";
        case Vote::Abstain: return "ABSTAIN";
    }
    return "UNKNOWN";
}

std::string to_string(QuorumOutcome o) {
    switch (o) {
        case QuorumOutcome::Allow: return "ALLOW";
        case QuorumOutcome::Deny: return "DENY";
        case QuorumOutcome::EscalateToHuman: return "ESCALATE_TO_HUMAN";
    }
    return "UNKNOWN";
}

QuorumVerifier::QuorumVerifier(std::vector<std::shared_ptr<Verifier>> verifiers,
                                int required_approvals)
    : verifiers_(std::move(verifiers)), required_approvals_(required_approvals) {}

QuorumResult QuorumVerifier::decide(const VerificationRequest& req) const {
    std::vector<VerifierVote> votes;
    votes.reserve(verifiers_.size());
    int approvals = 0, denies = 0, abstains = 0;

    for (const auto& v : verifiers_) {
        VerifierVote vote = v->vote(req);
        if (vote.verifier_id.empty()) vote.verifier_id = v->id();
        switch (vote.vote) {
            case Vote::Approve: ++approvals; break;
            case Vote::Deny: ++denies; break;
            case Vote::Abstain: ++abstains; break;
        }
        votes.push_back(vote);
    }

    if (denies > 0) {
        return {QuorumOutcome::Deny,
                "at least one verifier denied — fail closed on disagreement", votes};
    }
    if (approvals >= required_approvals_) {
        return {QuorumOutcome::Allow,
                std::to_string(approvals) + " of " + std::to_string(verifiers_.size()) +
                    " verifiers approved with zero denies",
                votes};
    }
    (void)abstains;
    return {QuorumOutcome::EscalateToHuman,
            "insufficient approvals (" + std::to_string(approvals) + "/" +
                std::to_string(required_approvals_) + " required) and no denies — no "
                "confident verdict either way",
            votes};
}

}  // namespace warden
