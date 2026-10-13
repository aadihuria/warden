#include "warden/quorum.hpp"

#include <future>

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
    // Verifiers are dispatched concurrently, not one after another. This
    // matters in practice: a real model-backed verifier (see
    // include/warden/anthropic_verifier.hpp) makes a blocking HTTP call
    // that can take hundreds of milliseconds, and running N verifiers
    // sequentially means paying that cost N times even though they're
    // independent, I/O-bound operations with nothing to wait on each
    // other for. Each verifier's vote() is launched on its own thread via
    // std::async and joined via future::get() before tallying, so total
    // quorum latency is bounded by the SLOWEST verifier, not the sum of
    // all of them.
    std::vector<std::future<VerifierVote>> futures;
    futures.reserve(verifiers_.size());
    for (const auto& v : verifiers_) {
        // Capture `v` BY VALUE (a shared_ptr copy -- cheap, just a
        // refcount bump) rather than by reference. Capturing the
        // range-for loop variable by reference here would be a real bug:
        // the reference's binding doesn't outlive the loop iteration the
        // way an async task running later needs it to. `req` is safe to
        // capture by reference since decide() blocks on every future
        // via get() before returning, so req's lifetime always covers
        // every verifier call.
        std::shared_ptr<Verifier> verifier = v;
        futures.push_back(std::async(std::launch::async, [verifier, &req]() {
            VerifierVote vote = verifier->vote(req);
            if (vote.verifier_id.empty()) vote.verifier_id = verifier->id();
            return vote;
        }));
    }

    std::vector<VerifierVote> votes;
    votes.reserve(futures.size());
    int approvals = 0, denies = 0, abstains = 0;
    for (auto& f : futures) {
        VerifierVote vote = f.get();
        switch (vote.vote) {
            case Vote::Approve: ++approvals; break;
            case Vote::Deny: ++denies; break;
            case Vote::Abstain: ++abstains; break;
        }
        votes.push_back(std::move(vote));
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
