#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "warden/ledger.hpp"

namespace warden {

// JSON (de)serialization for a list of LedgerEvents, used over the wire.
// Lives here rather than in ledger.hpp/cpp to keep the core ledger data
// structure free of a JSON dependency (consistent with the rest of
// warden_core -- see e.g. quorum.hpp's plain key/value argument_fields).
std::string events_to_json(const std::vector<LedgerEvent>& events);
std::vector<LedgerEvent> events_from_json(const std::string& json_str);

// A version vector: for each replica_id, the highest lamport_clock
// already known from that replica. This is what makes replication
// delta-state rather than full-state: a peer sends this alongside its
// request, and the server only returns events with a higher clock than
// what the requester already has for that specific origin replica (an
// event's "origin" is its own replica_id, which is stable regardless of
// how many times it's been re-merged elsewhere -- see CrdtLedger).
using VersionVector = std::unordered_map<std::string, uint64_t>;

// Computes the version vector for a set of events: the max lamport_clock
// seen per replica_id.
VersionVector compute_version_vector(const std::vector<LedgerEvent>& events);

// Compact, URL-safe encoding: "replica_id:clock,replica_id:clock,...".
// replica_ids are generated as plain hex strings (see gen_span_id() in
// proxy_main.cpp), so no percent-encoding is needed -- this stays
// correct as long as that invariant holds, which is asserted in
// tests/test_replication.cpp rather than just assumed.
std::string encode_version_vector(const VersionVector& vv);
VersionVector decode_version_vector(const std::string& encoded);

// Filters `events` down to only those with lamport_clock strictly
// greater than what `since` already has for that event's replica_id
// (missing replica_id in `since` is treated as clock 0, i.e. "send
// everything from a replica I've never seen").
std::vector<LedgerEvent> delta_since(const std::vector<LedgerEvent>& events,
                                      const VersionVector& since);

// A minimal HTTP/1.1 server exposing exactly two routes over a real TCP
// socket, hand-rolled rather than pulling in a web framework for a
// two-endpoint protocol surface:
//
//   GET  /ledger/events[?since=<version vector>]
//        -> 200, this replica's events as JSON. With `since`, only
//           events strictly newer (per origin replica) than what the
//           requester already has -- DELTA-state sync, not full-state:
//           a long-running pair of replicas exchange only what actually
//           changed since their last sync, not the whole ledger every
//           time.
//   POST /ledger/sync    -> pulls GET /ledger/events (with this
//                           replica's own version vector attached) from
//                           every peer, merges, responds with how many
//                           were new
//
// This is the actual network transport that was explicitly left
// unimplemented at the end of M4 (NOTES.md) -- CrdtLedger::merge_events()
// already has the tested merge algorithm; this is what moves bytes
// between two real, separate processes.
class ReplicationServer {
public:
    // get_events_json: given the requester's version vector (empty
    //                   VersionVector{} means "send everything"), returns
    //                   the delta as serialized JSON.
    // sync_now: pulls from all configured peers (attaching this
    //           replica's own version vector to each request) and
    //           merges; returns the number of newly-merged events.
    ReplicationServer(int port, std::vector<std::string> peers,
                       std::function<std::string(const VersionVector&)> get_events_json,
                       std::function<int()> sync_now);
    ~ReplicationServer();

    ReplicationServer(const ReplicationServer&) = delete;
    ReplicationServer& operator=(const ReplicationServer&) = delete;

    // Starts the accept loop on a background thread. Returns false (and
    // leaves the server not running) if the port couldn't be bound.
    bool start();
    void stop();

    const std::vector<std::string>& peers() const { return peers_; }

private:
    void accept_loop();
    void handle_connection(int client_fd);

    int port_;
    std::vector<std::string> peers_;
    std::function<std::string(const VersionVector&)> get_events_json_;
    std::function<int()> sync_now_;
    std::atomic<bool> running_{false};
    // atomic, not plain int: stop() (main thread) and accept_loop()
    // (accept thread) both touch this concurrently during shutdown.
    // ThreadSanitizer caught a real data race here when this was a plain
    // int -- see NOTES.md.
    std::atomic<int> listen_fd_{-1};
    std::thread accept_thread_;
};

// Fetches another replica's /ledger/events over HTTP (via libcurl),
// attaching `local_version_vector` as a `?since=` query parameter so the
// peer only sends back its delta. Pass an empty VersionVector to request
// everything (e.g. on first contact with a peer). Returns true and fills
// `out_json` on success; false (with `out_json` unspecified) on any
// network/HTTP failure -- a peer being unreachable is an expected,
// non-fatal condition, not an error to propagate.
bool fetch_peer_events_json(const std::string& peer_base_url,
                             const VersionVector& local_version_vector, std::string& out_json);

}  // namespace warden
