#include "warden/taint.hpp"

#include <algorithm>

namespace warden {

std::string to_string(TrustTier tier) {
    switch (tier) {
        case TrustTier::UntrustedExternal: return "UNTRUSTED_EXTERNAL";
        case TrustTier::UntrustedInternal: return "UNTRUSTED_INTERNAL";
        case TrustTier::Operator: return "OPERATOR";
        case TrustTier::Principal: return "PRINCIPAL";
    }
    return "UNKNOWN";
}

std::optional<TrustTier> trust_tier_from_string(const std::string& s) {
    if (s == "UNTRUSTED_EXTERNAL") return TrustTier::UntrustedExternal;
    if (s == "UNTRUSTED_INTERNAL") return TrustTier::UntrustedInternal;
    if (s == "OPERATOR") return TrustTier::Operator;
    if (s == "PRINCIPAL") return TrustTier::Principal;
    return std::nullopt;
}

TrustTier join_min(TrustTier a, TrustTier b) {
    return static_cast<TrustTier>(std::min(static_cast<int>(a), static_cast<int>(b)));
}

void TaintLineage::absorb(const ProvenanceEnvelope& env, double span_confidence) {
    min_trust_tier = join_min(min_trust_tier, env.trust_tier);
    contributing_span_ids.push_back(env.span_id);
    confidence = std::max(confidence, span_confidence);
}

}  // namespace warden
