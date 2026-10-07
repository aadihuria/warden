// Warden MCP proxy — M0.
//
// Sits between an MCP client (e.g. Claude) and a real downstream MCP
// server, speaking the same newline-delimited JSON-RPC stdio transport on
// both sides. It is transparent for every message except "tools/call":
//
//   1. On a tools/call REQUEST (client -> us -> child), it looks up the
//      tool's static risk class and evaluates it against the current
//      session taint state (see below) with warden::PolicyEngine. If the
//      decision isn't Allow, the request is never forwarded to the child —
//      we synthesize an MCP error result and return it to the client
//      directly.
//
//   2. On a tools/call RESPONSE (child -> us -> client), if the tool is
//      configured as "ingests_untrusted" (reads web pages, email, etc.),
//      the response content is stored as a Span (actual text, not just a
//      hash) before being forwarded on unchanged.
//
// Taint is now attributed PER ACTION (see M1 fix in NOTES.md), not at
// whole-session granularity: when a high-risk tool call comes in, its
// argument text is compared against every known span's content via
// warden::attribute_taint() (token-overlap heuristic — see
// include/warden/attribution.hpp), and only spans with real textual
// overlap contribute taint to THIS action's TaintLineage. An action
// whose arguments have nothing to do with any untrusted span is
// evaluated as clean, even if the session touched untrusted content
// elsewhere. This replaced an earlier whole-session-taint version after
// M1 benchmarking measured a 100% false-positive rate on ordinary
// read-then-communicate workflows under the old approach — see NOTES.md
// for the measured before/after.

#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "json.hpp"
#include "warden/attribution.hpp"
#include "warden/policy.hpp"
#include "warden/quorum.hpp"
#include "warden/taint.hpp"
#include "warden/verifiers.hpp"

using json = nlohmann::json;
using namespace warden;

namespace {

std::string gen_span_id() {
    static std::mt19937_64 rng{std::random_device{}()};
    std::ostringstream oss;
    oss << std::hex << rng() << rng();
    return oss.str();
}

// Non-cryptographic content fingerprint. Good enough to distinguish spans
// for M0's audit log; swap for a real digest (e.g. SHA-256) before the
// content_hash field is relied on for anything security-relevant like
// ledger integrity (see DESIGN.md section 4.4, which needs cryptographic
// hash-chaining, not this).
uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

int64_t now_unix_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Concatenates every string/number leaf value in a JSON value into one
// text blob, for comparing a tool call's arguments against known spans.
// Keys are deliberately ignored — we care about the content being passed
// around, not argument names.
void collect_text(const json& j, std::string& out) {
    if (j.is_string()) {
        out += ' ';
        out += j.get<std::string>();
    } else if (j.is_number()) {
        out += ' ';
        out += j.dump();
    } else if (j.is_object()) {
        for (auto& [k, v] : j.items()) {
            (void)k;
            collect_text(v, out);
        }
    } else if (j.is_array()) {
        for (auto& v : j) collect_text(v, out);
    }
}

struct ToolConfig {
    bool ingests_untrusted = false;
    ActionRiskClass risk_class = ActionRiskClass::ReversibleWrite;
};

// Pulls each top-level string argument value into a flat list, for
// verifiers that need to inspect specific fields (e.g. "to", "channel")
// without the quorum/verifier library depending on a JSON parser.
std::vector<std::pair<std::string, std::string>> extract_string_fields(const json& args) {
    std::vector<std::pair<std::string, std::string>> fields;
    if (args.is_object()) {
        for (auto& [k, v] : args.items()) {
            if (v.is_string()) fields.emplace_back(k, v.get<std::string>());
        }
    }
    return fields;
}

std::string truncate(const std::string& s, size_t max_len) {
    return s.size() <= max_len ? s : s.substr(0, max_len) + "...";
}

class AuditLog {
public:
    explicit AuditLog(const std::string& path) : out_(path, std::ios::app) {}

    void record(const json& entry) {
        std::lock_guard<std::mutex> lk(mu_);
        json e = entry;
        e["ts_unix_ms"] = now_unix_ms();
        out_ << e.dump() << std::endl;
        std::cerr << "[warden] " << e.dump() << std::endl;
    }

private:
    std::mutex mu_;
    std::ofstream out_;
};

// One JSON-RPC message per line, no embedded newlines — this matches the
// MCP stdio transport framing.
bool read_line(FILE* f, std::string& out) {
    out.clear();
    int c;
    bool any = false;
    while ((c = fgetc(f)) != EOF) {
        any = true;
        if (c == '\n') return true;
        out.push_back(static_cast<char>(c));
    }
    return any;
}

void write_line(FILE* f, const std::string& line, std::mutex& write_mu) {
    std::lock_guard<std::mutex> lk(write_mu);
    fwrite(line.data(), 1, line.size(), f);
    fputc('\n', f);
    fflush(f);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: warden-proxy <config.json>\n";
        return 1;
    }

    std::ifstream cfg_file(argv[1]);
    if (!cfg_file) {
        std::cerr << "warden: cannot open config file: " << argv[1] << "\n";
        return 1;
    }
    json cfg;
    try {
        cfg_file >> cfg;
    } catch (const std::exception& e) {
        std::cerr << "warden: invalid config JSON: " << e.what() << "\n";
        return 1;
    }

    std::vector<std::string> cmd;
    try {
        cmd = cfg.at("downstream_command").get<std::vector<std::string>>();
    } catch (const std::exception&) {
        std::cerr << "warden: config must have a \"downstream_command\" array\n";
        return 1;
    }
    if (cmd.empty()) {
        std::cerr << "warden: downstream_command must not be empty\n";
        return 1;
    }

    std::unordered_map<std::string, ToolConfig> tools;
    if (cfg.contains("tools")) {
        for (auto& [name, spec] : cfg["tools"].items()) {
            ToolConfig tc;
            tc.ingests_untrusted = spec.value("ingests_untrusted", false);
            auto rc = action_risk_class_from_string(
                spec.value("risk_class", std::string("REVERSIBLE_WRITE")));
            tc.risk_class = rc.value_or(ActionRiskClass::ReversibleWrite);
            tools[name] = tc;
        }
    }

    AuditLog audit(cfg.value("audit_log", std::string("warden-audit.log")));

    // --- spawn the real downstream MCP server as a child process ---
    int in_pipe[2];   // we write -> child reads (child stdin)
    int out_pipe[2];  // child writes -> we read (child stdout)
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
        perror("warden: pipe");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("warden: fork");
        return 1;
    }
    if (pid == 0) {
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);

        std::vector<char*> cargv;
        cargv.reserve(cmd.size() + 1);
        for (auto& s : cmd) cargv.push_back(const_cast<char*>(s.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        perror("warden: execvp (downstream MCP server)");
        _exit(127);
    }

    close(in_pipe[0]);
    close(out_pipe[1]);
    FILE* child_stdin = fdopen(in_pipe[1], "w");
    FILE* child_stdout = fdopen(out_pipe[0], "r");
    if (!child_stdin || !child_stdout) {
        std::cerr << "warden: fdopen failed\n";
        return 1;
    }

    std::mutex spans_mu;
    std::vector<Span> known_spans;

    std::mutex pending_mu;
    std::unordered_map<std::string, std::string> pending_tool_by_id;  // json id dump -> tool name

    std::mutex stdout_write_mu;
    std::mutex child_stdin_write_mu;

    PolicyEngine policy;

    // M3 quorum: three independent stub verifiers (see
    // include/warden/verifiers.hpp for why these specific ones and what
    // "independent" means for deterministic stand-ins). Destination
    // allowlist is read from config so each deployment can set its own
    // trusted domains/channels; defaults to an empty allowlist (denies
    // every destination) if not configured, which is the fail-closed
    // default — an operator must opt in to trusted destinations.
    std::vector<std::string> trusted_destinations;
    if (cfg.contains("trusted_destinations")) {
        trusted_destinations = cfg["trusted_destinations"].get<std::vector<std::string>>();
    }
    int required_approvals = cfg.value("quorum_required_approvals", 2);

    QuorumVerifier quorum(
        {std::make_shared<KeywordInjectionVerifier>(),
         std::make_shared<ArgumentDestinationVerifier>(
             std::vector<std::string>{"to", "channel"}, trusted_destinations),
         std::make_shared<AlwaysApproveVerifier>()},
        required_approvals);

    // child stdout -> our stdout, tagging taint on untrusted-content tool
    // responses as they pass through.
    std::thread reader_thread([&]() {
        std::string raw;
        while (read_line(child_stdout, raw)) {
            try {
                json msg = json::parse(raw);
                if (msg.contains("id") && msg.contains("result")) {
                    std::string id_key = msg["id"].dump();
                    std::string tool_name;
                    {
                        std::lock_guard<std::mutex> lk(pending_mu);
                        auto it = pending_tool_by_id.find(id_key);
                        if (it != pending_tool_by_id.end()) {
                            tool_name = it->second;
                            pending_tool_by_id.erase(it);
                        }
                    }
                    auto tc_it = tools.find(tool_name);
                    if (!tool_name.empty() && tc_it != tools.end() &&
                        tc_it->second.ingests_untrusted) {
                        std::string content_text;
                        collect_text(msg["result"], content_text);

                        Span span;
                        span.span_id = gen_span_id();
                        span.source_id = tool_name;
                        span.trust_tier = TrustTier::UntrustedExternal;
                        span.content = content_text;

                        {
                            std::lock_guard<std::mutex> lk(spans_mu);
                            known_spans.push_back(span);
                        }
                        audit.record({{"event", "ingest"},
                                       {"tool", tool_name},
                                       {"span_id", span.span_id},
                                       {"trust_tier", to_string(span.trust_tier)},
                                       {"content_hash", std::to_string(fnv1a(content_text))}});
                    }
                }
            } catch (const std::exception&) {
                // Not a JSON-RPC message we care about tagging — pass through.
            }
            write_line(stdout, raw, stdout_write_mu);
        }
    });

    // our stdin (from the client) -> child stdin, intercepting tools/call.
    std::string raw;
    while (read_line(stdin, raw)) {
        bool forward = true;
        try {
            json msg = json::parse(raw);
            if (msg.value("method", std::string()) == "tools/call" && msg.contains("params")) {
                std::string tool_name = msg["params"].value("name", std::string());

                ActionRiskClass risk = ActionRiskClass::ReversibleWrite;
                auto tc_it = tools.find(tool_name);
                if (tc_it != tools.end()) risk = tc_it->second.risk_class;

                std::string action_text;
                if (msg["params"].contains("arguments")) {
                    collect_text(msg["params"]["arguments"], action_text);
                }

                std::vector<Span> spans_snapshot;
                {
                    std::lock_guard<std::mutex> lk(spans_mu);
                    spans_snapshot = known_spans;
                }

                TaintLineage lineage = attribute_taint(action_text, spans_snapshot);
                PolicyResult pres = policy.evaluate({tool_name, risk, lineage});

                audit.record({{"event", "decision"},
                               {"tool", tool_name},
                               {"risk_class", to_string(risk)},
                               {"decision", pres.decision == Decision::Allow     ? "allow"
                                             : pres.decision == Decision::Deny   ? "deny"
                                                                                  : "escalate"},
                               {"reason", pres.reason},
                               {"action_min_trust_tier", to_string(lineage.min_trust_tier)},
                               {"action_confidence", lineage.confidence},
                               {"matched_span_ids", lineage.contributing_span_ids}});

                bool allowed = pres.decision == Decision::Allow;
                std::string block_reason = pres.reason;

                if (pres.decision == Decision::EscalateToQuorum) {
                    VerificationRequest vreq;
                    vreq.tool_name = tool_name;
                    vreq.risk_class = risk;
                    vreq.confidence = lineage.confidence;
                    if (msg["params"].contains("arguments")) {
                        vreq.argument_fields = extract_string_fields(msg["params"]["arguments"]);
                    }
                    for (const auto& span_id : lineage.contributing_span_ids) {
                        for (const auto& span : spans_snapshot) {
                            if (span.span_id == span_id) {
                                vreq.evidence.push_back(
                                    {span.span_id, span.trust_tier, truncate(span.content, 300)});
                                break;
                            }
                        }
                    }

                    QuorumResult qres = quorum.decide(vreq);
                    json votes_json = json::array();
                    for (const auto& v : qres.votes) {
                        votes_json.push_back({{"verifier", v.verifier_id},
                                               {"vote", to_string(v.vote)},
                                               {"justification", v.justification}});
                    }
                    audit.record({{"event", "quorum_decision"},
                                   {"tool", tool_name},
                                   {"outcome", to_string(qres.outcome)},
                                   {"reason", qres.reason},
                                   {"votes", votes_json}});

                    allowed = qres.outcome == QuorumOutcome::Allow;
                    block_reason = "policy escalated to quorum (" + pres.reason +
                                    "); quorum outcome " + to_string(qres.outcome) + ": " +
                                    qres.reason;
                }

                if (!allowed) {
                    forward = false;
                    json resp = {{"jsonrpc", "2.0"},
                                  {"id", msg.value("id", json(nullptr))},
                                  {"result",
                                   {{"isError", true},
                                    {"content",
                                     json::array({{{"type", "text"},
                                                    {"text", "Warden blocked this action: " +
                                                                 block_reason}}})}}}};
                    write_line(stdout, resp.dump(), stdout_write_mu);
                } else if (msg.contains("id")) {
                    std::lock_guard<std::mutex> lk(pending_mu);
                    pending_tool_by_id[msg["id"].dump()] = tool_name;
                }
            }
        } catch (const std::exception&) {
            // Not JSON-RPC we need to interpret — pass through unchanged.
        }

        if (forward) {
            write_line(child_stdin, raw, child_stdin_write_mu);
        }
    }

    fclose(child_stdin);
    reader_thread.join();
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
