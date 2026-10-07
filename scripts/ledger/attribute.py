#!/usr/bin/env python3
"""Reads a Warden audit log (now a hash-chained CrdtLedger, see
include/warden/ledger.hpp), verifies the chain's integrity independently
of the C++ code that wrote it, and walks a blocked/denied decision's
matched_span_ids back to the exact ingest event (tool + trust tier) that
caused the taint -- the attribution tool DESIGN.md section 4.4 calls for.

Usage:
    python3 scripts/ledger/attribute.py <audit-log-file> [--verify-only]

With no --verify-only, after verifying the chain it prints attribution
for every "deny" or "quorum_decision" (DENY/ESCALATE_TO_HUMAN) event: the
decision itself, plus the ingest event(s) that supplied its taint.
"""
import argparse
import hashlib
import json
import sys


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_events(path):
    events = []
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append((line_no, json.loads(line)))
            except json.JSONDecodeError as e:
                print(f"line {line_no}: not valid JSON ({e}), skipping", file=sys.stderr)
    return events


def verify_chain(events):
    """Independently recomputes each event's hash and checks per-replica
    chain linkage, exactly mirroring warden::CrdtLedger::find_tampered_event
    but in Python, against the persisted file -- not trusting the C++
    process that wrote it."""
    by_replica = {}
    for line_no, ev in events:
        by_replica.setdefault(ev["replica_id"], []).append((line_no, ev))

    problems = []
    for replica_id, chain in by_replica.items():
        chain.sort(key=lambda t: t[1]["lamport_clock"])
        expected_prev = ""
        for line_no, ev in chain:
            recomputed = sha256_hex(
                f"{ev['replica_id']}|{ev['lamport_clock']}|{ev['prev_hash']}|{ev['payload']}"
            )
            if recomputed != ev["content_hash"]:
                problems.append(
                    f"line {line_no} (replica {replica_id}, clock {ev['lamport_clock']}): "
                    f"content_hash does not match recomputed hash -- payload was tampered with"
                )
            if ev["prev_hash"] != expected_prev:
                problems.append(
                    f"line {line_no} (replica {replica_id}, clock {ev['lamport_clock']}): "
                    f"prev_hash does not match the previous event in this replica's chain "
                    f"-- an event was inserted, removed, or reordered"
                )
            expected_prev = ev["content_hash"]
    return problems


def attribute(events):
    by_span_id = {}  # span_id -> (line_no, ingest payload)
    decisions = []

    for line_no, ev in events:
        payload = json.loads(ev["payload"])
        if payload.get("event") == "ingest":
            by_span_id[payload["span_id"]] = (line_no, payload)
        elif payload.get("event") in ("decision", "quorum_decision"):
            decisions.append((line_no, payload))

    for line_no, payload in decisions:
        blocked = payload.get("decision") in ("deny",) or payload.get("outcome") in (
            "DENY", "ESCALATE_TO_HUMAN",
        )
        if not blocked:
            continue

        print(f"\n=== line {line_no}: {payload.get('event')} on tool "
              f"\"{payload.get('tool')}\" ===")
        print(f"  outcome: {payload.get('decision') or payload.get('outcome')}")
        print(f"  reason: {payload.get('reason')}")

        span_ids = payload.get("matched_span_ids", [])
        if not span_ids:
            print("  (no matched spans recorded -- not attributable to a specific ingest event)")
            continue

        print("  attributed to:")
        for span_id in span_ids:
            if span_id in by_span_id:
                src_line, src = by_span_id[span_id]
                print(f"    - line {src_line}: ingested by tool \"{src['tool']}\" "
                      f"(trust_tier={src['trust_tier']}, span_id={span_id})")
            else:
                print(f"    - span_id {span_id}: no matching ingest event found in this log "
                      f"(may be in a different replica's log not yet merged in)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("audit_log")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    events = load_events(args.audit_log)
    print(f"loaded {len(events)} events from {args.audit_log}")

    problems = verify_chain(events)
    if problems:
        print(f"\nCHAIN VERIFICATION FAILED ({len(problems)} problem(s)):")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    print("chain verification OK -- no tampering detected")

    if not args.verify_only:
        attribute(events)


if __name__ == "__main__":
    main()
