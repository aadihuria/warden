#include "test_framework.hpp"
#include "warden/taint.hpp"

using namespace warden;

TEST_CASE("join_min picks the lower-trust tier") {
    REQUIRE(join_min(TrustTier::Principal, TrustTier::UntrustedExternal) ==
            TrustTier::UntrustedExternal);
    REQUIRE(join_min(TrustTier::Operator, TrustTier::UntrustedInternal) ==
            TrustTier::UntrustedInternal);
    REQUIRE(join_min(TrustTier::Principal, TrustTier::Operator) == TrustTier::Operator);
}

TEST_CASE("join_min is commutative and idempotent") {
    REQUIRE(join_min(TrustTier::Operator, TrustTier::Principal) ==
            join_min(TrustTier::Principal, TrustTier::Operator));
    REQUIRE(join_min(TrustTier::Operator, TrustTier::Operator) == TrustTier::Operator);
}

TEST_CASE("TaintLineage starts clean and degrades monotonically on absorb") {
    TaintLineage lineage;
    REQUIRE(lineage.min_trust_tier == TrustTier::Principal);
    REQUIRE(lineage.contributing_span_ids.empty());

    ProvenanceEnvelope op_env{"span-1", "config:policy.yaml", TrustTier::Operator, "hash1", 0};
    lineage.absorb(op_env, 1.0);
    REQUIRE(lineage.min_trust_tier == TrustTier::Operator);
    REQUIRE(lineage.contributing_span_ids.size() == 1);

    ProvenanceEnvelope web_env{"span-2", "fetch_url:evil.example", TrustTier::UntrustedExternal,
                                "hash2", 1};
    lineage.absorb(web_env, 1.0);
    // Taint can only get worse (lower trust), never better, once a low-trust
    // span has contributed — this is the core safety property of the lattice.
    REQUIRE(lineage.min_trust_tier == TrustTier::UntrustedExternal);
    REQUIRE(lineage.contributing_span_ids.size() == 2);

    ProvenanceEnvelope clean_env{"span-3", "user:turn", TrustTier::Principal, "hash3", 2};
    lineage.absorb(clean_env, 1.0);
    // A later trusted input does NOT wash out earlier taint still present
    // in the session/context — this is the property that stops a
    // prompt-injection payload from being "forgotten" by adding more
    // trusted turns on top.
    REQUIRE(lineage.min_trust_tier == TrustTier::UntrustedExternal);
}

TEST_CASE("TaintLineage confidence tracks the max observed span confidence") {
    TaintLineage lineage;
    ProvenanceEnvelope env{"span-1", "src", TrustTier::UntrustedExternal, "hash", 0};
    lineage.absorb(env, 0.4);
    REQUIRE(lineage.confidence == 0.4);
    lineage.absorb(env, 0.9);
    REQUIRE(lineage.confidence == 0.9);
    lineage.absorb(env, 0.2);
    REQUIRE(lineage.confidence == 0.9);
}

TEST_CASE("trust tier string round-trip") {
    for (auto tier : {TrustTier::UntrustedExternal, TrustTier::UntrustedInternal,
                       TrustTier::Operator, TrustTier::Principal}) {
        auto parsed = trust_tier_from_string(to_string(tier));
        REQUIRE(parsed.has_value());
        REQUIRE(*parsed == tier);
    }
    REQUIRE(!trust_tier_from_string("NOT_A_TIER").has_value());
}
