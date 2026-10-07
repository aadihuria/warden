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
//      the response content is folded into the session's TaintLineage as
//      an UNTRUSTED_EXTERNAL span before being forwarded on unchanged.
//
// IMPORTANT M0 SIMPLIFICATION (see DESIGN.md section 4.1 and NOTES.md):
// taint is tracked at SESSION granularity here, not via the citation-based
// per-action dataflow the full design calls for. That means: once any
// untrusted content has been read in a session, Warden conservatively
// treats every subsequent high-risk action as potentially justified by it,
// until the session ends. This is the correct fail-closed default for a
// first milestone, and it is exactly what the M0 deliverable in
// DESIGN.md asks for ("a crafted poisoned webpage causes a deny/escalate
// that an unprotected setup would have allowed") — but it will over-block
// in a long-running session that reads untrusted content once and then
// does unrelated high-risk work. Per-action citation-based taint
// (DESIGN.md 4.1) is the fix, scheduled for M1/M2.

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
#include "warden/policy.hpp"
#include "warden/taint.hpp"

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

struct ToolConfig {
    bool ingests_untrusted = false;
    ActionRiskClass risk_class = ActionRiskClass::ReversibleWrite;
};

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

    std::mutex taint_mu;
    TaintLineage session_taint;

    std::mutex pending_mu;
    std::unordered_map<std::string, std::string> pending_tool_by_id;  // json id dump -> tool name

    std::mutex stdout_write_mu;
    std::mutex child_stdin_write_mu;

    PolicyEngine policy;

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
                        ProvenanceEnvelope env;
                        env.span_id = gen_span_id();
                        env.source_id = tool_name;
                        env.trust_tier = TrustTier::UntrustedExternal;
                        env.content_hash = std::to_string(fnv1a(msg["result"].dump()));
                        env.ingested_at_unix_ms = now_unix_ms();

                        TrustTier new_min;
                        {
                            std::lock_guard<std::mutex> lk(taint_mu);
                            session_taint.absorb(env, 1.0);
                            new_min = session_taint.min_trust_tier;
                        }
                        audit.record({{"event", "ingest"},
                                       {"tool", tool_name},
                                       {"span_id", env.span_id},
                                       {"trust_tier", to_string(env.trust_tier)},
                                       {"session_min_trust_tier", to_string(new_min)}});
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

                TaintLineage snapshot;
                {
                    std::lock_guard<std::mutex> lk(taint_mu);
                    snapshot = session_taint;
                }

                PolicyResult pres = policy.evaluate({tool_name, risk, snapshot});

                audit.record({{"event", "decision"},
                               {"tool", tool_name},
                               {"risk_class", to_string(risk)},
                               {"decision", pres.decision == Decision::Allow     ? "allow"
                                             : pres.decision == Decision::Deny   ? "deny"
                                                                                  : "escalate"},
                               {"reason", pres.reason},
                               {"session_min_trust_tier", to_string(snapshot.min_trust_tier)}});

                if (pres.decision != Decision::Allow) {
                    forward = false;
                    json resp = {{"jsonrpc", "2.0"},
                                  {"id", msg.value("id", json(nullptr))},
                                  {"result",
                                   {{"isError", true},
                                    {"content",
                                     json::array({{{"type", "text"},
                                                    {"text", "Warden blocked this action: " +
                                                                 pres.reason}}})}}}};
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
