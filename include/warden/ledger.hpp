#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace warden {

std::string sha256_hex(const std::string& data);

// A single hash-chained event, content-addressed: `content_hash` is
// derived from every other field, so it doubles as this event's unique
// id (tampering with any field changes the hash, which is exactly the
// property an audit record needs).
struct LedgerEvent {
    std::string replica_id;
    uint64_t lamport_clock = 0;
    std::string prev_hash;  // "" for the first event in this replica's own chain
    std::string payload;    // caller-serialized event data (e.g. a JSON string)
    std::string content_hash;
};

// A replicated, mergeable, tamper-evident audit log (DESIGN.md 4.4).
//
// Each Warden instance is its own "replica" with its own strictly
// sequential, hash-chained log of the decisions IT made. merge() is a
// plain OR-Set union keyed by content_hash: two replicas that recorded
// independent decisions during a network partition (or just two Warden
// instances that never talked to each other) can be merged in either
// order, repeatedly, and end up with an identical combined view — that's
// what "commutative, associative, idempotent" means in practice, and
// it's exactly what's unit-tested in tests/test_ledger.cpp rather than
// just asserted.
//
// This is the mergeable DATA STRUCTURE and algorithm; the actual network
// transport that moves events between live replicas lives in
// include/warden/replication.hpp (a minimal hand-rolled HTTP sync layer,
// not gRPC — see NOTES.md for why).
class CrdtLedger {
public:
    explicit CrdtLedger(std::string replica_id);

    // Appends a new event to this replica's OWN chain.
    LedgerEvent append(const std::string& payload);

    // OR-Set union: every event in `other` not already present (by
    // content_hash) is added. Safe to call repeatedly / in any order.
    void merge(const CrdtLedger& other);

    // Same OR-Set union, but from a raw event list (e.g. events received
    // over the network, see include/warden/replication.hpp) rather than
    // another CrdtLedger instance, and returns only the events that were
    // ACTUALLY new (not already present) -- callers that need to persist
    // only the delta (not re-write everything) use this instead of merge().
    std::vector<LedgerEvent> merge_events(const std::vector<LedgerEvent>& events);

    // All known events (this replica's own plus anything merged in),
    // in a deterministic total order: (lamport_clock, replica_id,
    // content_hash). Two replicas that merged the same events via
    // different paths/orders produce the identical ordered sequence.
    std::vector<LedgerEvent> ordered_events() const;

    size_t size() const { return events_.size(); }

    // Verifies every replica's own hash chain is unbroken: recomputes
    // each event's hash from its fields and checks prev_hash linkage
    // within that replica's sequence. Returns the content_hash of the
    // first event that fails verification, or nullopt if everything
    // checks out.
    std::optional<std::string> find_tampered_event() const;

    const std::string& replica_id() const { return replica_id_; }

    // TEST-ONLY hooks to simulate an attacker/operator editing a
    // persisted ledger after the fact (e.g. hand-editing a JSON-lines
    // file on disk) without going through append()/merge(). These exist
    // so find_tampered_event() can be verified against a real corrupted
    // state instead of just asserted to work. Never call these outside
    // tests.
    void debug_corrupt_payload_for_testing(const std::string& content_hash,
                                            const std::string& new_payload);
    void debug_remove_event_for_testing(const std::string& content_hash);

private:
    std::string replica_id_;
    uint64_t local_clock_ = 0;
    std::string local_tip_hash_;
    std::unordered_map<std::string, LedgerEvent> events_;  // keyed by content_hash
};

}  // namespace warden
