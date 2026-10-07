#include "test_framework.hpp"
#include "warden/policy.hpp"

using namespace warden;

namespace {

TaintLineage clean() {
    TaintLineage t;
    t.min_trust_tier = TrustTier::Principal;
    return t;
}

TaintLineage tainted_external(double confidence = 1.0) {
    TaintLineage t;
    t.min_trust_tier = TrustTier::UntrustedExternal;
    t.confidence = confidence;
    return t;
}

TaintLineage tainted_internal() {
    TaintLineage t;
    t.min_trust_tier = TrustTier::UntrustedInternal;
    return t;
}

}  // namespace

TEST_CASE("READ_ONLY is always allowed, tainted or not") {
    PolicyEngine policy;
    auto r1 = policy.evaluate({"fetch_url", ActionRiskClass::ReadOnly, tainted_external()});
    REQUIRE(r1.decision == Decision::Allow);

    auto r2 = policy.evaluate({"fetch_url", ActionRiskClass::ReadOnly, clean()});
    REQUIRE(r2.decision == Decision::Allow);
}

TEST_CASE("EXTERNAL_COMM justified by untrusted external content is denied") {
    PolicyEngine policy;
    auto r = policy.evaluate({"send_email", ActionRiskClass::ExternalComm, tainted_external()});
    REQUIRE(r.decision == Decision::Deny);
}

TEST_CASE("EXTERNAL_COMM with clean provenance is allowed") {
    PolicyEngine policy;
    auto r = policy.evaluate({"send_email", ActionRiskClass::ExternalComm, clean()});
    REQUIRE(r.decision == Decision::Allow);
}

TEST_CASE("EXTERNAL_COMM tainted only by an unverified internal agent escalates") {
    PolicyEngine policy;
    auto r = policy.evaluate({"send_email", ActionRiskClass::ExternalComm, tainted_internal()});
    REQUIRE(r.decision == Decision::EscalateToQuorum);
}

TEST_CASE("IRREVERSIBLE_WRITE with any taint escalates to quorum") {
    PolicyEngine policy;
    auto r = policy.evaluate(
        {"delete_file", ActionRiskClass::IrreversibleWrite, tainted_external()});
    REQUIRE(r.decision == Decision::EscalateToQuorum);
}

TEST_CASE("IRREVERSIBLE_WRITE with clean provenance is allowed") {
    PolicyEngine policy;
    auto r = policy.evaluate({"delete_file", ActionRiskClass::IrreversibleWrite, clean()});
    REQUIRE(r.decision == Decision::Allow);
}

TEST_CASE("CODE_EXEC with any taint escalates to quorum") {
    PolicyEngine policy;
    auto r = policy.evaluate({"run_shell", ActionRiskClass::CodeExec, tainted_internal()});
    REQUIRE(r.decision == Decision::EscalateToQuorum);
}

TEST_CASE("REVERSIBLE_WRITE tolerates internal taint but not external") {
    PolicyEngine policy;
    auto r_internal =
        policy.evaluate({"write_file", ActionRiskClass::ReversibleWrite, tainted_internal()});
    REQUIRE(r_internal.decision == Decision::Allow);

    auto r_external =
        policy.evaluate({"write_file", ActionRiskClass::ReversibleWrite, tainted_external()});
    REQUIRE(r_external.decision == Decision::EscalateToQuorum);
}

TEST_CASE("action_risk_class string round-trip") {
    for (auto c : {ActionRiskClass::ReadOnly, ActionRiskClass::ReversibleWrite,
                    ActionRiskClass::IrreversibleWrite, ActionRiskClass::ExternalComm,
                    ActionRiskClass::Financial, ActionRiskClass::CodeExec}) {
        auto parsed = action_risk_class_from_string(to_string(c));
        REQUIRE(parsed.has_value());
        REQUIRE(*parsed == c);
    }
}
