#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "warden/ledger.hpp"

namespace warden {

// JSON (de)serialization for a list of LedgerEvents, used over the wire.
// Lives here rather than in ledger.hpp/cpp to keep the core ledger data
// structure free of a JSON dependency (consistent with the rest of
// warden_core -- see e.g. quorum.hpp's plain key/value argument_fields).
std::string events_to_json(const std::vector<LedgerEvent>& events);
std::vector<LedgerEvent> events_from_json(const std::string& json_str);

// A minimal HTTP/1.1 server exposing exactly two routes over a real TCP
// socket, hand-rolled rather than pulling in a web framework for a
// two-endpoint protocol surface:
//
//   GET  /ledger/events  -> 200, this replica's current events as JSON
//   POST /ledger/sync    -> pulls GET /ledger/events from every peer,
//                           merges, responds with how many were new
//
// This is the actual network transport that was explicitly left
// unimplemented at the end of M4 (NOTES.md) -- CrdtLedger::merge_events()
// already has the tested merge algorithm; this is what moves bytes
// between two real, separate processes.
class ReplicationServer {
public:
    // get_events_json: returns this replica's current events, serialized.
    // sync_now: pulls from all configured peers and merges; returns the
    //           number of newly-merged events.
    ReplicationServer(int port, std::vector<std::string> peers,
                       std::function<std::string()> get_events_json,
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
    std::function<std::string()> get_events_json_;
    std::function<int()> sync_now_;
    std::atomic<bool> running_{false};
    int listen_fd_ = -1;
    std::thread accept_thread_;
};

// Fetches another replica's /ledger/events over HTTP (via libcurl).
// Returns true and fills `out_json` on success; false (with `out_json`
// unspecified) on any network/HTTP failure -- a peer being unreachable
// is an expected, non-fatal condition, not an error to propagate.
bool fetch_peer_events_json(const std::string& peer_base_url, std::string& out_json);

}  // namespace warden
