#include "test_framework.hpp"
#include "warden/ledger.hpp"

using namespace warden;

TEST_CASE("sha256_hex matches the known test vector for an empty string") {
    // Standard SHA-256 known-answer test -- if this fails, the vendored
    // implementation itself is broken, not our wrapper.
    REQUIRE(sha256_hex("") ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("sha256_hex matches the known test vector for \"abc\"") {
    REQUIRE(sha256_hex("abc") ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("append produces a valid, self-verifying chain") {
    CrdtLedger ledger("replica-a");
    ledger.append("event one");
    ledger.append("event two");
    ledger.append("event three");

    REQUIRE(ledger.size() == 3);
    REQUIRE(!ledger.find_tampered_event().has_value());
}

TEST_CASE("the first event in a chain has an empty prev_hash (genesis)") {
    CrdtLedger ledger("replica-a");
    auto ev = ledger.append("first");
    REQUIRE(ev.prev_hash.empty());
    REQUIRE(!ev.content_hash.empty());
}

TEST_CASE("each event's prev_hash equals the previous event's content_hash") {
    CrdtLedger ledger("replica-a");
    auto ev1 = ledger.append("first");
    auto ev2 = ledger.append("second");
    REQUIRE(ev2.prev_hash == ev1.content_hash);
}

TEST_CASE("two different payloads never collide in content_hash") {
    CrdtLedger ledger("replica-a");
    auto ev1 = ledger.append("payload A");
    auto ev2 = ledger.append("payload B");
    REQUIRE(ev1.content_hash != ev2.content_hash);
}

TEST_CASE("find_tampered_event detects a corrupted payload") {
    CrdtLedger ledger("replica-a");
    auto ev1 = ledger.append("original payload");
    ledger.append("second event");

    ledger.debug_corrupt_payload_for_testing(ev1.content_hash, "corrupted payload");
    auto tampered = ledger.find_tampered_event();
    REQUIRE(tampered.has_value());
    REQUIRE(*tampered == ev1.content_hash);
}

TEST_CASE("find_tampered_event detects a removed (deleted) middle event") {
    CrdtLedger ledger("replica-a");
    ledger.append("first");
    auto ev2 = ledger.append("second");
    ledger.append("third");

    ledger.debug_remove_event_for_testing(ev2.content_hash);
    // the third event's prev_hash now points at a hash that no longer
    // exists in the chain -- that's a detectable break.
    REQUIRE(ledger.find_tampered_event().has_value());
}

TEST_CASE("an untampered multi-replica merged ledger has no tampered events") {
    CrdtLedger a("replica-a");
    a.append("a1");
    a.append("a2");
    CrdtLedger b("replica-b");
    b.append("b1");

    CrdtLedger merged("replica-a");  // id doesn't matter once we're just merging
    merged.merge(a);
    merged.merge(b);
    REQUIRE(!merged.find_tampered_event().has_value());
}

// --- CRDT algebraic properties: these are the properties that make
// merge() safe to call in any order, any number of times, across
// replicas that never coordinated -- not just asserted, actually tested.

TEST_CASE("merge is idempotent: merging the same ledger twice changes nothing") {
    CrdtLedger a("replica-a");
    a.append("x");
    a.append("y");

    CrdtLedger merged("replica-a");
    merged.merge(a);
    size_t after_first = merged.size();
    merged.merge(a);
    REQUIRE(merged.size() == after_first);
    REQUIRE(merged.size() == 2);
}

TEST_CASE("merge is commutative: merge(A,B) == merge(B,A) as an ordered sequence") {
    CrdtLedger a("replica-a");
    a.append("a1");
    a.append("a2");
    CrdtLedger b("replica-b");
    b.append("b1");

    CrdtLedger ab("x");
    ab.merge(a);
    ab.merge(b);

    CrdtLedger ba("y");
    ba.merge(b);
    ba.merge(a);

    auto ordered_ab = ab.ordered_events();
    auto ordered_ba = ba.ordered_events();
    REQUIRE(ordered_ab.size() == ordered_ba.size());
    for (size_t i = 0; i < ordered_ab.size(); ++i) {
        REQUIRE(ordered_ab[i].content_hash == ordered_ba[i].content_hash);
    }
}

TEST_CASE("merge is associative: merge(merge(A,B),C) == merge(A,merge(B,C))") {
    CrdtLedger a("replica-a");
    a.append("a1");
    CrdtLedger b("replica-b");
    b.append("b1");
    CrdtLedger c("replica-c");
    c.append("c1");

    CrdtLedger left("x");
    left.merge(a);
    left.merge(b);
    left.merge(c);

    CrdtLedger bc("y");
    bc.merge(b);
    bc.merge(c);
    CrdtLedger right("z");
    right.merge(a);
    right.merge(bc);

    auto left_events = left.ordered_events();
    auto right_events = right.ordered_events();
    REQUIRE(left_events.size() == right_events.size());
    for (size_t i = 0; i < left_events.size(); ++i) {
        REQUIRE(left_events[i].content_hash == right_events[i].content_hash);
    }
}

TEST_CASE("partition-heal: two replicas record independently, then merge with no loss or duplication") {
    // Simulates exactly the scenario DESIGN.md 4.4 calls out: two Warden
    // instances partitioned from each other each record real decisions,
    // then the partition heals and they merge.
    CrdtLedger replica1("replica-1");
    replica1.append("decision: allow send_email to finance@co.com");
    replica1.append("decision: deny delete_file /backups/db.tar.gz");

    CrdtLedger replica2("replica-2");
    replica2.append("decision: allow read_transactions");
    replica2.append("decision: escalate book_reservation to quorum");
    replica2.append("decision: quorum DENY book_reservation");

    CrdtLedger healed("merged-view");
    healed.merge(replica1);
    healed.merge(replica2);

    REQUIRE(healed.size() == 5);  // no events lost
    REQUIRE(!healed.find_tampered_event().has_value());

    // merging again (e.g. a retry after a flaky network call) must not
    // duplicate anything.
    healed.merge(replica1);
    healed.merge(replica2);
    REQUIRE(healed.size() == 5);
}

TEST_CASE("ordered_events gives a deterministic order regardless of merge path") {
    CrdtLedger a("replica-a");
    a.append("a1");
    a.append("a2");
    a.append("a3");

    // Merge via several different intermediate paths and confirm they
    // all converge to the identical ordered sequence.
    CrdtLedger direct("x");
    direct.merge(a);

    CrdtLedger via_empty_hop("y");
    CrdtLedger empty("empty");
    via_empty_hop.merge(empty);
    via_empty_hop.merge(a);
    via_empty_hop.merge(empty);

    auto direct_order = direct.ordered_events();
    auto hop_order = via_empty_hop.ordered_events();
    REQUIRE(direct_order.size() == hop_order.size());
    for (size_t i = 0; i < direct_order.size(); ++i) {
        REQUIRE(direct_order[i].content_hash == hop_order[i].content_hash);
    }
}
