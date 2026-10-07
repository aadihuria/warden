#include "warden/attribution.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_set>

namespace warden {

namespace {

bool is_token_char(unsigned char c) {
    return std::isalnum(c) || c == '@' || c == '.' || c == '_' || c == '-';
}

}  // namespace

std::vector<std::string> tokenize(const std::string& text, size_t min_token_length) {
    std::vector<std::string> tokens;
    std::string current;
    auto flush = [&]() {
        if (current.size() >= min_token_length) tokens.push_back(current);
        current.clear();
    };
    for (unsigned char c : text) {
        if (is_token_char(c)) {
            current.push_back(static_cast<char>(std::tolower(c)));
        } else {
            flush();
        }
    }
    flush();
    return tokens;
}

double overlap_coefficient(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    if (a.empty() || b.empty()) return 0.0;
    std::unordered_set<std::string> set_a(a.begin(), a.end());
    std::unordered_set<std::string> set_b(b.begin(), b.end());
    const auto& smaller = set_a.size() <= set_b.size() ? set_a : set_b;
    const auto& larger = set_a.size() <= set_b.size() ? set_b : set_a;
    size_t intersection = 0;
    for (const auto& tok : smaller) {
        if (larger.count(tok)) ++intersection;
    }
    return static_cast<double>(intersection) / static_cast<double>(smaller.size());
}

TaintLineage attribute_taint(const std::string& action_text, const std::vector<Span>& known_spans,
                              double match_threshold) {
    TaintLineage lineage;  // starts clean: min_trust_tier = Principal, confidence = 0
    auto action_tokens = tokenize(action_text);
    if (action_tokens.empty()) return lineage;

    for (const auto& span : known_spans) {
        auto span_tokens = tokenize(span.content);
        double score = overlap_coefficient(action_tokens, span_tokens);
        if (score >= match_threshold) {
            ProvenanceEnvelope env;
            env.span_id = span.span_id;
            env.source_id = span.source_id;
            env.trust_tier = span.trust_tier;
            lineage.absorb(env, score);
        }
    }
    return lineage;
}

}  // namespace warden
