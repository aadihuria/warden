#include "warden/ledger.hpp"

#include <algorithm>
#include <sstream>

extern "C" {
#include "sha256.h"
}

namespace warden {

std::string sha256_hex(const std::string& data) {
    SHA256_CTX ctx;
    unsigned char digest[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    sha256_final(&ctx, digest);

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_BLOCK_SIZE * 2);
    for (unsigned char b : digest) {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

namespace {

std::string compute_hash(const std::string& replica_id, uint64_t lamport_clock,
                          const std::string& prev_hash, const std::string& payload) {
    std::ostringstream oss;
    oss << replica_id << '|' << lamport_clock << '|' << prev_hash << '|' << payload;
    return sha256_hex(oss.str());
}

}  // namespace

CrdtLedger::CrdtLedger(std::string replica_id) : replica_id_(std::move(replica_id)) {}

LedgerEvent CrdtLedger::append(const std::string& payload) {
    ++local_clock_;
    LedgerEvent ev;
    ev.replica_id = replica_id_;
    ev.lamport_clock = local_clock_;
    ev.prev_hash = local_tip_hash_;
    ev.payload = payload;
    ev.content_hash = compute_hash(ev.replica_id, ev.lamport_clock, ev.prev_hash, ev.payload);

    local_tip_hash_ = ev.content_hash;
    events_[ev.content_hash] = ev;
    return ev;
}

void CrdtLedger::merge(const CrdtLedger& other) {
    for (const auto& [hash, ev] : other.events_) {
        events_.emplace(hash, ev);  // no-op if already present -- OR-Set union
    }
}

std::vector<LedgerEvent> CrdtLedger::merge_events(const std::vector<LedgerEvent>& events) {
    std::vector<LedgerEvent> newly_added;
    for (const auto& ev : events) {
        if (events_.emplace(ev.content_hash, ev).second) {
            newly_added.push_back(ev);
        }
    }
    return newly_added;
}

std::vector<LedgerEvent> CrdtLedger::ordered_events() const {
    std::vector<LedgerEvent> out;
    out.reserve(events_.size());
    for (const auto& [hash, ev] : events_) out.push_back(ev);

    std::sort(out.begin(), out.end(), [](const LedgerEvent& a, const LedgerEvent& b) {
        if (a.lamport_clock != b.lamport_clock) return a.lamport_clock < b.lamport_clock;
        if (a.replica_id != b.replica_id) return a.replica_id < b.replica_id;
        return a.content_hash < b.content_hash;
    });
    return out;
}

void CrdtLedger::debug_corrupt_payload_for_testing(const std::string& content_hash,
                                                     const std::string& new_payload) {
    auto it = events_.find(content_hash);
    if (it != events_.end()) it->second.payload = new_payload;
}

void CrdtLedger::debug_remove_event_for_testing(const std::string& content_hash) {
    events_.erase(content_hash);
}

std::optional<std::string> CrdtLedger::find_tampered_event() const {
    // Group by replica_id, verify each replica's chain independently.
    std::unordered_map<std::string, std::vector<LedgerEvent>> by_replica;
    for (const auto& [hash, ev] : events_) {
        (void)hash;
        by_replica[ev.replica_id].push_back(ev);
    }

    for (auto& [replica_id, chain] : by_replica) {
        (void)replica_id;
        std::sort(chain.begin(), chain.end(), [](const LedgerEvent& a, const LedgerEvent& b) {
            return a.lamport_clock < b.lamport_clock;
        });

        std::string expected_prev;  // "" for the genesis event
        for (const auto& ev : chain) {
            std::string recomputed =
                compute_hash(ev.replica_id, ev.lamport_clock, ev.prev_hash, ev.payload);
            if (recomputed != ev.content_hash) return ev.content_hash;
            if (ev.prev_hash != expected_prev) return ev.content_hash;
            expected_prev = ev.content_hash;
        }
    }
    return std::nullopt;
}

}  // namespace warden
