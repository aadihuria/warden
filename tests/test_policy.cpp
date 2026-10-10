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

TaintLineage tainted_operator() {
    TaintLineage t;
    t.min_trust_tier = TrustTier::Operator;
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

TEST_CASE("EXTERNAL_COMM linked to untrusted external content always escalates to quorum") {
    // Used to deny directly above a confidence threshold, bypassing the
    // quorum entirely -- changed after benchmarking showed that high
    // overlap confidence also fires on LEGITIMATE verbatim content relay
    // (e.g. forwarding a link the agent just read), which only the
    // quorum's destination-aware check can actually distinguish from a
    // real attack. See src/policy.cpp and NOTES.md for the full story.
    PolicyEngine policy;
    auto r_high = policy.evaluate(
        {"send_email", ActionRiskClass::ExternalComm, tainted_external(/*confidence=*/0.9)});
    REQUIRE(r_high.decision == Decision::EscalateToQuorum);

    auto r_low = policy.evaluate(
        {"send_email", ActionRiskClass::ExternalComm, tainted_external(/*confidence=*/0.2)});
    REQUIRE(r_low.decision == Decision::EscalateToQuorum);
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

TEST_CASE("EXTERNAL_COMM tainted only at OPERATOR tier is allowed") {
    // OPERATOR means the agent's own config/system prompt, not attacker
    // content — this must not be treated the same as UNTRUSTED_* (see
    // DESIGN.md 4.1's trust lattice). The current rule only checks for
    // UNTRUSTED_EXTERNAL / UNTRUSTED_INTERNAL explicitly, so OPERATOR falls
    // through to allow — pinning that down so a future refactor to a
    // generic "tainted = tier != Principal" check doesn't silently start
    // blocking operator-sourced actions too.
    PolicyEngine policy;
    auto r = policy.evaluate({"send_email", ActionRiskClass::ExternalComm, tainted_operator()});
    REQUIRE(r.decision == Decision::Allow);
}

TEST_CASE("REVERSIBLE_WRITE tolerates OPERATOR taint") {
    PolicyEngine policy;
    auto r = policy.evaluate({"write_file", ActionRiskClass::ReversibleWrite, tainted_operator()});
    REQUIRE(r.decision == Decision::Allow);
}

TEST_CASE("FINANCIAL with any taint escalates, clean is allowed") {
    PolicyEngine policy;
    auto r_tainted =
        policy.evaluate({"transfer_funds", ActionRiskClass::Financial, tainted_external()});
    REQUIRE(r_tainted.decision == Decision::EscalateToQuorum);

    auto r_clean = policy.evaluate({"transfer_funds", ActionRiskClass::Financial, clean()});
    REQUIRE(r_clean.decision == Decision::Allow);
}

TEST_CASE("FINANCIAL escalates even on the lightest taint (OPERATOR)") {
    // FINANCIAL is deliberately stricter than REVERSIBLE_WRITE: ANY
    // non-principal provenance escalates, not just UNTRUSTED_EXTERNAL.
    PolicyEngine policy;
    auto r = policy.evaluate({"transfer_funds", ActionRiskClass::Financial, tainted_operator()});
    REQUIRE(r.decision == Decision::EscalateToQuorum);
}

TEST_CASE("empty tool_name does not crash policy evaluation") {
    PolicyEngine policy;
    auto r = policy.evaluate({"", ActionRiskClass::ExternalComm, tainted_external()});
    REQUIRE(r.decision == Decision::EscalateToQuorum);
}

TEST_CASE("an out-of-range risk class value falls through to the conservative default") {
    // Guards against UB-adjacent surprises if a risk class ever reaches the
    // engine without going through action_risk_class_from_string (e.g. a
    // future caller that casts a raw int). The engine must fail closed,
    // not silently allow.
    PolicyEngine policy;
    auto bogus = static_cast<ActionRiskClass>(99);
    auto r = policy.evaluate({"mystery_tool", bogus, clean()});
    REQUIRE(r.decision == Decision::EscalateToQuorum);
}

TEST_CASE("action_risk_class_from_string rejects unknown and empty strings") {
    REQUIRE(!action_risk_class_from_string("").has_value());
    REQUIRE(!action_risk_class_from_string("read_only").has_value());
    REQUIRE(!action_risk_class_from_string("NOT_A_CLASS").has_value());
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
