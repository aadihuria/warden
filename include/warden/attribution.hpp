#pragma once

#include <string>
#include <vector>

#include "warden/taint.hpp"

namespace warden {

// A piece of previously-ingested content, with its actual text retained
// (not just a hash) so later actions can be compared against it.
struct Span {
    std::string span_id;
    std::string source_id;
    TrustTier trust_tier;
    std::string content;
};

std::vector<std::string> tokenize(const std::string& text, size_t min_token_length = 4);

// Overlap coefficient: |A ∩ B| / min(|A|, |B|), 0 if either is empty.
// Deliberately asymmetric-in-spirit (normalized by the SMALLER set): we
// care whether the action's own (usually short) text is substantially
// drawn from a given span, not whether the two texts are similar overall.
double overlap_coefficient(const std::vector<std::string>& a, const std::vector<std::string>& b);

// Approximates DESIGN.md section 4.1 item 2's citation/embedding-
// similarity fallback: instead of requiring the agent to cite span_ids
// (which needs client-side cooperation we don't have over plain MCP) or
// running a real embedding model (which costs money/network per call),
// this does token-overlap between the proposed action's text and every
// known span's content. A span only contributes to the returned
// TaintLineage if the overlap meets `match_threshold` — this is what
// makes taint attribution PER-ACTION instead of whole-session: an action
// whose text has nothing to do with any untrusted span stays clean even
// if the session touched untrusted content elsewhere.
//
// This is a heuristic, not a formal guarantee — see NOTES.md for the
// known failure mode (legitimate reuse of fetched content looks similar
// to malicious reuse under plain text overlap) and what a real citation
// or embedding-based approach would need to do better.
TaintLineage attribute_taint(const std::string& action_text, const std::vector<Span>& known_spans,
                              double match_threshold = 0.15);

}  // namespace warden
