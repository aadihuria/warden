#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace warden {

// Trust lattice, lowest trust first. Taint propagation is a join-semilattice:
// combining content from multiple sources always yields the MINIMUM trust
// tier among them ("no read up" — see DESIGN.md section 4.1).
enum class TrustTier : int {
    UntrustedExternal = 0,
    UntrustedInternal = 1,
    Operator = 2,
    Principal = 3,
};

std::string to_string(TrustTier tier);
std::optional<TrustTier> trust_tier_from_string(const std::string& s);

// Join operation on the trust lattice: taint only flows downward.
TrustTier join_min(TrustTier a, TrustTier b);

// Provenance envelope attached to a single piece of ingested content
// (one MCP tool response, one RAG chunk, one inbound message).
struct ProvenanceEnvelope {
    std::string span_id;    // stable id for propagation tracking
    std::string source_id;  // e.g. "fetch_url:https://example.com/..."
    TrustTier trust_tier = TrustTier::UntrustedExternal;
    std::string content_hash;
    int64_t ingested_at_unix_ms = 0;
};

// Accumulated taint state for a reasoning session (or, in the full design,
// for a single action's justification once citation-based propagation is
// implemented — see DESIGN.md section 4.1, item 2, and NOTES.md for what
// this M0 implementation approximates).
struct TaintLineage {
    TrustTier min_trust_tier = TrustTier::Principal;
    std::vector<std::string> contributing_span_ids;
    double confidence = 0.0;  // 0..1 confidence in this lineage attribution

    // Fold a newly-ingested provenance envelope into the lineage.
    void absorb(const ProvenanceEnvelope& env, double span_confidence);
};

}  // namespace warden
