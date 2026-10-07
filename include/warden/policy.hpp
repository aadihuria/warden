#pragma once

#include <optional>
#include <string>

#include "warden/taint.hpp"

namespace warden {

// Static per-tool risk classification (DESIGN.md section 4.2).
enum class ActionRiskClass {
    ReadOnly,
    ReversibleWrite,
    IrreversibleWrite,
    ExternalComm,
    Financial,
    CodeExec,
};

std::string to_string(ActionRiskClass c);
std::optional<ActionRiskClass> action_risk_class_from_string(const std::string& s);

enum class Decision {
    Allow,
    Deny,
    EscalateToQuorum,  // M0: no quorum service exists yet, so the proxy
                        // currently treats this the same as Deny and says
                        // so in the reason string. Wire up to the real
                        // quorum verifier in M3.
};

struct PolicyInput {
    std::string tool_name;
    ActionRiskClass risk_class;
    TaintLineage taint_lineage;
};

struct PolicyResult {
    Decision decision;
    std::string reason;
};

// M0 policy engine: a small, fixed set of taint-aware rules matching the
// example policy in DESIGN.md section 4.2. This is intentionally NOT a
// general-purpose policy DSL/VM yet (see DESIGN.md: "don't over-engineer
// with a full Rego VM initially") — that's a later milestone once the
// core taint-aware evaluation model is validated.
class PolicyEngine {
public:
    PolicyResult evaluate(const PolicyInput& input) const;
};

}  // namespace warden
