#!/usr/bin/env python3
"""Edge-case checks against the live warden-proxy binary. Not policy unit
tests (those live in tests/test_policy.cpp) -- these are about the proxy
process itself not crashing or hanging on malformed/unusual input, and
failing safe when it doesn't recognize something.

Run from the repo root: python3 scripts/proxy_edge_cases.py
"""
import json
import subprocess
import sys

FAILURES = []


def start_proxy():
    return subprocess.Popen(
        ["./build/warden-proxy", "scripts/demo.warden.json"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )


def check(name, proc, raw_line, expect_reply):
    proc.stdin.write(raw_line + "\n")
    proc.stdin.flush()
    if not expect_reply:
        return
    line = proc.stdout.readline()
    if not line:
        FAILURES.append(f"{name}: proxy produced no reply (may have crashed/hung)")
        return
    try:
        json.loads(line)
    except json.JSONDecodeError:
        FAILURES.append(f"{name}: reply wasn't valid JSON: {line!r}")


def case_malformed_json():
    proc = start_proxy()
    # not JSON at all -- proxy must not crash, and since it can't be
    # interpreted as tools/call it should just pass through to the child,
    # which will also ignore it. No reply expected.
    check("malformed json", proc, "not even json {{{", expect_reply=False)
    # confirm the proxy is still alive and answers a normal request after
    # seeing garbage.
    proc.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "fetch_url", "arguments": {"url": "https://example.com"}},
    }) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        FAILURES.append("malformed json: proxy died instead of recovering")
    proc.stdin.close()
    proc.wait(timeout=5)


def case_unknown_tool():
    proc = start_proxy()
    # Tool not present in config.tools at all -- proxy defaults it to
    # REVERSIBLE_WRITE (see proxy_main.cpp). With a clean session that's
    # Allow, so it should be forwarded to the child, which will itself
    # reply with a JSON-RPC error for an unrecognized tool. Either way the
    # proxy must not crash and must produce *some* reply.
    check("unknown tool", proc, json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "totally_made_up_tool", "arguments": {}},
    }), expect_reply=True)
    proc.stdin.close()
    proc.wait(timeout=5)


def case_tools_call_missing_params():
    proc = start_proxy()
    # method is tools/call but there's no "params" key at all.
    check("tools/call with no params", proc, json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    }), expect_reply=False)
    proc.stdin.close()
    proc.wait(timeout=5)


def case_tools_call_missing_arguments():
    proc = start_proxy()
    # params present but no "arguments" key -- tool name is send_email
    # (EXTERNAL_COMM) on a clean session, should still be policy-evaluated
    # and allowed through without crashing on the missing field.
    check("tools/call with no arguments field", proc, json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "send_email"},
    }), expect_reply=True)
    proc.stdin.close()
    proc.wait(timeout=5)


def case_request_with_no_id():
    proc = start_proxy()
    # JSON-RPC notifications (no "id") are legal. A tools/call without an
    # id is unusual but must not crash the proxy.
    check("tools/call notification with no id", proc, json.dumps({
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "send_email", "arguments": {"to": "x", "body": "y"}},
    }), expect_reply=True)
    proc.stdin.close()
    proc.wait(timeout=5)


def case_empty_lines():
    proc = start_proxy()
    check("blank line", proc, "", expect_reply=False)
    check("whitespace-only line", proc, "   ", expect_reply=False)
    proc.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "fetch_url", "arguments": {"url": "https://example.com"}},
    }) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        FAILURES.append("empty lines: proxy died instead of recovering")
    proc.stdin.close()
    proc.wait(timeout=5)


if __name__ == "__main__":
    for fn in [case_malformed_json, case_unknown_tool, case_tools_call_missing_params,
               case_tools_call_missing_arguments, case_request_with_no_id, case_empty_lines]:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except subprocess.TimeoutExpired:
            FAILURES.append(f"{fn.__name__}: proxy hung (did not exit after stdin closed)")
            print(f"[FAIL] {fn.__name__}: timed out")

    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s):")
        for f in FAILURES:
            print(" -", f)
        sys.exit(1)
    print("\nall edge cases handled without crashing")
