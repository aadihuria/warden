#pragma once

#include <string>

#include "warden/quorum.hpp"

namespace warden {

// A real, model-backed verifier: sends the proposed action + evidence to
// the Anthropic Messages API and asks it to vote Approve/Deny/Abstain
// with a justification. This is the actual fix for the structural gap
// documented in NOTES.md's M3 section — keyword/destination stub
// verifiers can't reason about intent, only match patterns, so they're
// evadable by paraphrase and blind to risk classes with no
// destination-like field (bookings, file deletions, etc). A model can
// reason about whether an action is consistent with what it's being told
// the evidence actually says, which neither stub can.
//
// Isolation property (DESIGN.md 4.3, corrected during M3): this verifier
// has no tool-execution capability of its own — it makes one HTTP call,
// parses a vote out of the response, and returns. Even if the model's
// own reasoning gets hijacked by adversarial content in the evidence
// excerpts, the worst outcome is a bad VOTE, never a real action, because
// there is no tool for it to call here.
//
// Requires a real Anthropic API key and makes a real (billed) API call
// per vote() invocation. See NOTES.md for cost/latency notes before
// wiring this into a production quorum or a large benchmark run.
class AnthropicVerifier : public Verifier {
public:
    // api_key: read from ANTHROPIC_API_KEY by the caller, never hardcoded
    // or logged. model: defaults to a small/cheap/fast model since this
    // is a bounded classification task, not open-ended reasoning -- using
    // the flagship model here would be a real, avoidable cost mistake.
    explicit AnthropicVerifier(std::string api_key,
                                std::string model = "claude-haiku-4-5-20251001",
                                std::string verifier_name = "anthropic_verifier");

    VerifierVote vote(const VerificationRequest& req) const override;
    std::string id() const override { return verifier_name_; }

private:
    std::string api_key_;
    std::string model_;
    std::string verifier_name_;
};

}  // namespace warden
