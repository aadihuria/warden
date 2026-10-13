#include "test_framework.hpp"
#include "warden/ledger.hpp"
#include "warden/replication.hpp"

using namespace warden;

TEST_CASE("events_to_json / events_from_json round-trip exactly") {
    CrdtLedger ledger("replica-a");
    ledger.append("first payload");
    ledger.append("second payload");

    auto original = ledger.ordered_events();
    std::string json_str = events_to_json(original);
    auto parsed = events_from_json(json_str);

    REQUIRE(parsed.size() == original.size());
    for (size_t i = 0; i < original.size(); ++i) {
        REQUIRE(parsed[i].replica_id == original[i].replica_id);
        REQUIRE(parsed[i].lamport_clock == original[i].lamport_clock);
        REQUIRE(parsed[i].prev_hash == original[i].prev_hash);
        REQUIRE(parsed[i].payload == original[i].payload);
        REQUIRE(parsed[i].content_hash == original[i].content_hash);
    }
}

TEST_CASE("events_from_json on empty array returns empty vector") {
    auto parsed = events_from_json("[]");
    REQUIRE(parsed.empty());
}

TEST_CASE("events_from_json on malformed JSON returns empty, doesn't throw") {
    auto parsed = events_from_json("not json at all {{{");
    REQUIRE(parsed.empty());
}

TEST_CASE("events_from_json on a JSON object (not array) returns empty") {
    auto parsed = events_from_json("{\"not\": \"an array\"}");
    REQUIRE(parsed.empty());
}

TEST_CASE("round-tripped events still pass hash-chain verification") {
    CrdtLedger a("replica-a");
    a.append("x");
    a.append("y");
    a.append("z");

    std::string json_str = events_to_json(a.ordered_events());
    auto parsed = events_from_json(json_str);

    CrdtLedger reconstructed("replica-b");  // id irrelevant, we're only merging
    reconstructed.merge_events(parsed);

    REQUIRE(reconstructed.size() == 3);
    REQUIRE(!reconstructed.find_tampered_event().has_value());
}

TEST_CASE("merge_events returns only the newly-added events") {
    CrdtLedger source("replica-a");
    auto ev1 = source.append("one");
    auto ev2 = source.append("two");

    CrdtLedger target("replica-b");
    auto newly_added_first = target.merge_events({ev1, ev2});
    REQUIRE(newly_added_first.size() == 2);

    // merging the same events again should report zero new ones.
    auto newly_added_second = target.merge_events({ev1, ev2});
    REQUIRE(newly_added_second.empty());
    REQUIRE(target.size() == 2);
}

TEST_CASE("merge_events with a mix of known and new events returns only the new ones") {
    CrdtLedger source("replica-a");
    auto ev1 = source.append("one");
    auto ev2 = source.append("two");

    CrdtLedger target("replica-b");
    target.merge_events({ev1});

    auto newly_added = target.merge_events({ev1, ev2});
    REQUIRE(newly_added.size() == 1);
    REQUIRE(newly_added[0].content_hash == ev2.content_hash);
}

// --- delta-CRDT: version vectors and delta computation ---

TEST_CASE("compute_version_vector tracks the max clock per replica") {
    CrdtLedger a("replica-a");
    a.append("a1");
    a.append("a2");
    CrdtLedger b("replica-b");
    b.append("b1");

    CrdtLedger merged("x");
    merged.merge(a);
    merged.merge(b);

    auto vv = compute_version_vector(merged.ordered_events());
    REQUIRE(vv.size() == 2);
    REQUIRE(vv.at("replica-a") == 2);
    REQUIRE(vv.at("replica-b") == 1);
}

TEST_CASE("compute_version_vector on empty events returns an empty vector") {
    auto vv = compute_version_vector({});
    REQUIRE(vv.empty());
}

TEST_CASE("version vector encode/decode round-trips exactly") {
    VersionVector vv = {{"replica-a", 5}, {"replica-b", 12}};
    std::string encoded = encode_version_vector(vv);
    VersionVector decoded = decode_version_vector(encoded);
    REQUIRE(decoded.size() == 2);
    REQUIRE(decoded.at("replica-a") == 5);
    REQUIRE(decoded.at("replica-b") == 12);
}

TEST_CASE("decode_version_vector on empty string returns empty vector") {
    REQUIRE(decode_version_vector("").empty());
}

TEST_CASE("decode_version_vector skips malformed entries instead of throwing") {
    // missing colon, empty clock, non-numeric clock, and one valid entry
    auto vv = decode_version_vector("badentry,replica-a:,replica-b:notanumber,replica-c:7");
    REQUIRE(vv.size() == 1);
    REQUIRE(vv.at("replica-c") == 7);
}

TEST_CASE("delta_since returns everything when since is empty") {
    CrdtLedger a("replica-a");
    a.append("a1");
    a.append("a2");
    auto delta = delta_since(a.ordered_events(), {});
    REQUIRE(delta.size() == 2);
}

TEST_CASE("delta_since excludes events already known per replica") {
    CrdtLedger a("replica-a");
    a.append("a1");
    a.append("a2");
    a.append("a3");

    VersionVector since = {{"replica-a", 1}};  // already have clock 1
    auto delta = delta_since(a.ordered_events(), since);
    REQUIRE(delta.size() == 2);
    for (const auto& ev : delta) REQUIRE(ev.lamport_clock > 1);
}

TEST_CASE("delta_since treats an unknown replica_id as clock 0 (send everything)") {
    CrdtLedger a("replica-a");
    a.append("a1");
    CrdtLedger b("replica-b");
    b.append("b1");

    CrdtLedger merged("x");
    merged.merge(a);
    merged.merge(b);

    // since only knows about replica-a at clock 1 -- replica-b is
    // completely unknown to the requester, so all of its events must
    // come through.
    VersionVector since = {{"replica-a", 1}};
    auto delta = delta_since(merged.ordered_events(), since);
    REQUIRE(delta.size() == 1);
    REQUIRE(delta[0].replica_id == "replica-b");
}

TEST_CASE("full delta sync round-trip: only new events cross the wire") {
    CrdtLedger source("replica-a");
    auto ev1 = source.append("first");
    auto ev2 = source.append("second");

    CrdtLedger target("replica-b");
    target.merge_events({ev1});  // target already has the first event

    VersionVector target_vv = compute_version_vector(target.ordered_events());
    auto delta = delta_since(source.ordered_events(), target_vv);
    REQUIRE(delta.size() == 1);
    REQUIRE(delta[0].content_hash == ev2.content_hash);

    auto newly_added = target.merge_events(delta);
    REQUIRE(newly_added.size() == 1);
    REQUIRE(target.size() == 2);
}
