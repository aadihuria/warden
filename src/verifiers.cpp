#include "warden/verifiers.hpp"

#include <algorithm>
#include <cctype>

namespace warden {

namespace {

std::string lowercase(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(),
                                                    suffix) == 0;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

}  // namespace

VerifierVote KeywordInjectionVerifier::vote(const VerificationRequest& req) const {
    // "ignore previous/prior instructions" and "ignore the ..." are two of
    // the most common injection phrasing families in the published
    // corpora (AgentDojo/InjecAgent-style payloads); "system:" / "<!--
    // system" target fake role markers. Broadened from an earlier,
    // narrower list after M3 benchmarking caught two attack scenarios
    // slipping through specifically because their phrasing ("ignore the
    // requested hotel", "ignore the summary request") didn't match a
    // too-literal "ignore the user" marker — see NOTES.md. This is a
    // real, structural limitation of keyword matching, not something a
    // bigger list fixes for good: any fixed phrase list is trivially
    // evaded by paraphrasing, which is exactly why this is one vote
    // among several, not the only line of defense, and why a real
    // model-backed verifier (reasoning about intent, not matching
    // strings) is the actual fix, not a longer list.
    static const std::vector<std::string> markers = {
        "ignore previous instructions", "ignore prior instructions", "ignore the",
        "disregard the",                "disregard previous",        "new instructions:",
        "system:",                      "<!-- system",
    };
    for (const auto& ev : req.evidence) {
        std::string lower = lowercase(ev.excerpt);
        for (const auto& marker : markers) {
            if (contains(lower, marker)) {
                return {id(), Vote::Deny,
                        "evidence span " + ev.span_id +
                            " contains injection-style phrasing (\"" + marker + "\")"};
            }
        }
    }
    return {id(), Vote::Approve, "no known injection phrasing found in evidence excerpts"};
}

ArgumentDestinationVerifier::ArgumentDestinationVerifier(
    std::vector<std::string> destination_fields,
    std::vector<std::string> trusted_suffixes_or_prefixes)
    : destination_fields_(std::move(destination_fields)),
      trusted_markers_(std::move(trusted_suffixes_or_prefixes)) {}

VerifierVote ArgumentDestinationVerifier::vote(const VerificationRequest& req) const {
    for (const auto& field_name : destination_fields_) {
        for (const auto& [key, value] : req.argument_fields) {
            if (key != field_name) continue;

            for (const auto& marker : trusted_markers_) {
                if (starts_with(value, marker) || ends_with(value, marker)) {
                    return {id(), Vote::Approve,
                            "destination \"" + value + "\" matches trusted marker \"" + marker +
                                "\""};
                }
            }
            return {id(), Vote::Deny,
                    "destination \"" + value + "\" (field \"" + field_name +
                        "\") does not match any trusted destination marker"};
        }
    }
    return {id(), Vote::Abstain, "action has no recognized destination field to check"};
}

VerifierVote AlwaysApproveVerifier::vote(const VerificationRequest&) const {
    return {id(), Vote::Approve, "stub verifier — always approves, see class docstring"};
}

}  // namespace warden
