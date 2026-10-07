#pragma once

#include <string>
#include <vector>

#include "warden/quorum.hpp"

namespace warden {

// Deterministic, free, no-network verifiers for M3. These are stand-ins
// for real independent model-backed verifiers (DESIGN.md section 4.3 —
// "different model or at minimum different system prompt per verifier")
// and are deliberately built on DIFFERENT signal sources from each other
// and from the primary token-overlap attribution heuristic
// (include/warden/attribution.hpp), so the quorum is testing real
// redundancy, not three copies of the same logic agreeing with itself.
// See NOTES.md for what plugging in a real model-backed verifier would
// change.

// Flags evidence excerpts containing classic prompt-injection phrasing
// ("ignore previous instructions", "system:", etc.). A real, if crude,
// defense technique in practice; here it's one independent signal among
// several, not the sole line of defense.
class KeywordInjectionVerifier : public Verifier {
public:
    VerifierVote vote(const VerificationRequest& req) const override;
    std::string id() const override { return "keyword_injection_verifier"; }
};

// Checks the action's own destination-like fields (looks for argument
// keys in `destination_fields`, e.g. "to"/"channel") against an
// allowlist of trusted suffixes/prefixes. Abstains if the action has no
// such field (e.g. a financial booking with no recipient field) — a
// destination check has nothing to say about those.
class ArgumentDestinationVerifier : public Verifier {
public:
    ArgumentDestinationVerifier(std::vector<std::string> destination_fields,
                                 std::vector<std::string> trusted_suffixes_or_prefixes);
    VerifierVote vote(const VerificationRequest& req) const override;
    std::string id() const override { return "argument_destination_verifier"; }

private:
    std::vector<std::string> destination_fields_;
    std::vector<std::string> trusted_markers_;
};

// Trivial always-approve verifier. Exists as an explicit placeholder for
// where a real third model-backed verifier would plug in (see
// DESIGN.md's N=3, 2-of-3 quorum) — it is NOT meant to represent real
// independent judgment on its own, and a quorum built only from this
// verifier plus denies-everything would be meaningless. It's a stub, not
// a security control by itself; see NOTES.md.
class AlwaysApproveVerifier : public Verifier {
public:
    VerifierVote vote(const VerificationRequest& req) const override;
    std::string id() const override { return "always_approve_stub_verifier"; }
};

}  // namespace warden
