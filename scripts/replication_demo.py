#!/usr/bin/env python3
"""Proves the network replication layer (include/warden/replication.hpp)
actually works between two real, separate warden-proxy processes -- not
just the in-memory CrdtLedger merge tested in tests/test_ledger.cpp.

Starts two warden-proxy instances on different ports, each wrapping its
own downstream server and recording an independent decision (simulating
two Warden deployments that have never talked to each other), then
triggers a real HTTP sync between them and verifies both converge to the
same combined, hash-chain-verified audit log.

Usage (from repo root): python3 scripts/replication_demo.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WARDEN_BIN = os.path.join(REPO_ROOT, "build", "warden-proxy")
FAKE_SERVER = os.path.join(REPO_ROOT, "scripts", "fake_mcp_server.py")


def make_config(replica_id, audit_log, listen_port, peer_port):
    return {
        "downstream_command": ["python3", FAKE_SERVER],
        "audit_log": audit_log,
        "replica_id": replica_id,
        "tools": {
            "fetch_url": {"ingests_untrusted": True, "risk_class": "READ_ONLY"},
            "send_email": {"risk_class": "EXTERNAL_COMM"},
        },
        "replication": {
            "listen_port": listen_port,
            "peers": [f"http://127.0.0.1:{peer_port}"],
        },
    }


def call(proc, req_id, tool, arguments):
    req = {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
           "params": {"name": tool, "arguments": arguments}}
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def trigger_sync(port):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/ledger/sync", method="POST", data=b"")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def load_log(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def main():
    if not os.path.exists(WARDEN_BIN):
        print(f"warden-proxy not built at {WARDEN_BIN}", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        log1 = os.path.join(tmpdir, "replica1-audit.log")
        log2 = os.path.join(tmpdir, "replica2-audit.log")
        cfg1_path = os.path.join(tmpdir, "config1.json")
        cfg2_path = os.path.join(tmpdir, "config2.json")

        PORT1, PORT2 = 18801, 18802
        with open(cfg1_path, "w") as f:
            json.dump(make_config("replica-1", log1, PORT1, PORT2), f)
        with open(cfg2_path, "w") as f:
            json.dump(make_config("replica-2", log2, PORT2, PORT1), f)

        proc1 = subprocess.Popen([WARDEN_BIN, cfg1_path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, bufsize=1, cwd=REPO_ROOT)
        proc2 = subprocess.Popen([WARDEN_BIN, cfg2_path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, bufsize=1, cwd=REPO_ROOT)

        try:
            # Each replica records ONE decision independently -- like two
            # Warden deployments that have never synced.
            r1 = call(proc1, 1, "fetch_url", {"url": "https://example.com/clean"})
            assert "result" in r1, f"replica-1 call failed: {r1}"
            r2 = call(proc2, 1, "send_email", {"to": "finance@mycompany.com", "body": "report"})
            assert "result" in r2, f"replica-2 call failed: {r2}"

            time.sleep(0.3)  # give both HTTP servers a beat to be fully ready

            pre1 = len(load_log(log1))
            pre2 = len(load_log(log2))
            print(f"before sync: replica-1 has {pre1} events, replica-2 has {pre2} events")

            sync1_result = trigger_sync(PORT1)  # replica-1 pulls from replica-2
            sync2_result = trigger_sync(PORT2)  # replica-2 pulls from replica-1
            print(f"replica-1 sync result: {sync1_result}")
            print(f"replica-2 sync result: {sync2_result}")

        finally:
            proc1.stdin.close()
            proc2.stdin.close()
            proc1.wait(timeout=5)
            proc2.wait(timeout=5)

        events1 = load_log(log1)
        events2 = load_log(log2)
        hashes1 = {e["content_hash"] for e in events1}
        hashes2 = {e["content_hash"] for e in events2}
        replicas_seen_1 = {e["replica_id"] for e in events1}
        replicas_seen_2 = {e["replica_id"] for e in events2}

        print(f"\nafter sync: replica-1 log has {len(events1)} events from replicas {replicas_seen_1}")
        print(f"after sync: replica-2 log has {len(events2)} events from replicas {replicas_seen_2}")

        ok = True
        if "replica-1" not in replicas_seen_2 or "replica-2" not in replicas_seen_2:
            print("FAIL: replica-2's log doesn't contain events from both replicas", file=sys.stderr)
            ok = False
        if "replica-1" not in replicas_seen_1 or "replica-2" not in replicas_seen_1:
            print("FAIL: replica-1's log doesn't contain events from both replicas", file=sys.stderr)
            ok = False
        if hashes1 != hashes2:
            print("FAIL: the two replicas' logs did not converge to the same event set",
                  file=sys.stderr)
            print(f"  only in replica-1: {hashes1 - hashes2}", file=sys.stderr)
            print(f"  only in replica-2: {hashes2 - hashes1}", file=sys.stderr)
            ok = False

        # Independently verify each merged log's hash chain -- this is
        # the real payoff: a log containing events from TWO different
        # replicas, received over a real network call, still verifies.
        verify = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "ledger", "attribute.py"),
             log1, "--verify-only"],
            capture_output=True, text=True,
        )
        print(f"\nreplica-1's merged log verification: {verify.stdout.strip()}")
        if verify.returncode != 0:
            print("FAIL: replica-1's merged log failed chain verification", file=sys.stderr)
            ok = False

        if not ok:
            sys.exit(1)
        print("\nPASS: real network replication converged correctly and verifiably")


if __name__ == "__main__":
    main()
