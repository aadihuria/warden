#include "warden/policy.hpp"

namespace warden {

std::string to_string(ActionRiskClass c) {
    switch (c) {
        case ActionRiskClass::ReadOnly: return "READ_ONLY";
        case ActionRiskClass::ReversibleWrite: return "REVERSIBLE_WRITE";
        case ActionRiskClass::IrreversibleWrite: return "IRREVERSIBLE_WRITE";
        case ActionRiskClass::ExternalComm: return "EXTERNAL_COMM";
        case ActionRiskClass::Financial: return "FINANCIAL";
        case ActionRiskClass::CodeExec: return "CODE_EXEC";
    }
    return "UNKNOWN";
}

std::optional<ActionRiskClass> action_risk_class_from_string(const std::string& s) {
    if (s == "READ_ONLY") return ActionRiskClass::ReadOnly;
    if (s == "REVERSIBLE_WRITE") return ActionRiskClass::ReversibleWrite;
    if (s == "IRREVERSIBLE_WRITE") return ActionRiskClass::IrreversibleWrite;
    if (s == "EXTERNAL_COMM") return ActionRiskClass::ExternalComm;
    if (s == "FINANCIAL") return ActionRiskClass::Financial;
    if (s == "CODE_EXEC") return ActionRiskClass::CodeExec;
    return std::nullopt;
}

PolicyResult PolicyEngine::evaluate(const PolicyInput& input) const {
    const TrustTier tier = input.taint_lineage.min_trust_tier;
    const bool tainted = tier != TrustTier::Principal;

    // READ_ONLY actions never touch the outside world, so they're always
    // allowed regardless of taint — matches DESIGN.md's example `allow`
    // rule for READ_ONLY.
    if (input.risk_class == ActionRiskClass::ReadOnly) {
        return {Decision::Allow, "read-only action"};
    }

    // EXTERNAL_COMM justified by untrusted external content is the
    // canonical "lethal trifecta" case (DESIGN.md section 1/4.2).
    //
    // IMPORTANT: this used to deny outright on confidence >= 0.4,
    // skipping the quorum entirely, on the reasoning that strong textual
    // overlap was more likely to be a real injection citation than a
    // coincidence. That reasoning turned out to be wrong in an important
    // way once a larger benchmark set was run (see NOTES.md): LEGITIMATE
    // actions that relay something the agent genuinely just read (a
    // meeting link, a ticket number) also produce high overlap
    // confidence, because the agent is, correctly, copying real content
    // verbatim. High overlap confidence means "this action is clearly
    // connected to this untrusted span" — it does NOT mean "this
    // connection is malicious." Only the quorum's destination-aware
    // check (ArgumentDestinationVerifier) can actually tell those apart,
    // so skipping the quorum on confidence alone was silently throwing
    // away the one signal that matters most. Always escalate instead —
    // confidence is still passed through to the quorum for its own use,
    // but it no longer gates a direct deny.
    if (input.risk_class == ActionRiskClass::ExternalComm) {
        if (tier == TrustTier::UntrustedExternal) {
            return {Decision::EscalateToQuorum,
                    "external communication linked to untrusted external content "
                    "(confidence=" + std::to_string(input.taint_lineage.confidence) +
                        ") — requires quorum"};
        }
        if (tier == TrustTier::UntrustedInternal) {
            return {Decision::EscalateToQuorum,
                    "external communication influenced by unverified "
                    "internal agent output — requires quorum"};
        }
        return {Decision::Allow, "external communication with clean provenance"};
    }

    // IRREVERSIBLE_WRITE / FINANCIAL / CODE_EXEC: any taint at all routes
    // to quorum — matches DESIGN.md's escalate rule for IRREVERSIBLE_WRITE,
    // extended to the other high-severity risk classes.
    if (input.risk_class == ActionRiskClass::IrreversibleWrite ||
        input.risk_class == ActionRiskClass::Financial ||
        input.risk_class == ActionRiskClass::CodeExec) {
        if (tainted) {
            return {Decision::EscalateToQuorum,
                    to_string(input.risk_class) +
                        " action with non-principal provenance — requires "
                        "quorum"};
        }
        return {Decision::Allow, "high-risk action with clean (principal) provenance"};
    }

    // REVERSIBLE_WRITE: only the lowest trust tier triggers escalation;
    // operator/internal-agent provenance is allowed through.
    if (input.risk_class == ActionRiskClass::ReversibleWrite) {
        if (tier == TrustTier::UntrustedExternal) {
            return {Decision::EscalateToQuorum,
                    "reversible write justified by untrusted external content "
                    "— requires quorum"};
        }
        return {Decision::Allow, "reversible write with acceptable provenance"};
    }

    // Fail closed on anything unclassified.
    return {Decision::EscalateToQuorum, "unclassified action — conservative default"};
}

}  // namespace warden
