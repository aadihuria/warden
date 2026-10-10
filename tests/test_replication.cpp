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
