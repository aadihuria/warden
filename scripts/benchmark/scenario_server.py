#!/usr/bin/env python3
"""Generic stdio MCP-ish server driven by a scenario JSON file.

Usage: scenario_server.py <scenario.json> <log.jsonl>

For every "tools/call" request it receives, it:
  1. looks up a scripted response in the scenario's "tool_script" (falls
     back to a generic "ok" echo of the arguments if the tool has no
     scripted response), and
  2. appends a record of the call -- tool name and arguments -- to the
     log file.

The log file is the ground truth for scoring: it only contains calls that
actually reached this process, i.e. calls Warden allowed through (when
Warden is in front) or every call unconditionally (when run with no
Warden, as the "unprotected" baseline).
"""
import json
import sys


def main():
    if len(sys.argv) != 3:
        print("usage: scenario_server.py <scenario.json> <log.jsonl>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        scenario = json.load(f)
    log_path = sys.argv[2]

    tool_script = scenario.get("tool_script", {})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        req_id = msg.get("id")

        if method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})

            with open(log_path, "a") as logf:
                logf.write(json.dumps({"tool": name, "arguments": args}) + "\n")

            if name in tool_script:
                text = tool_script[name]
            else:
                text = f"ok: {name} called with {json.dumps(args)}"

            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": text}]},
            }) + "\n")
            sys.stdout.flush()
        elif method == "initialize":
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"protocolVersion": "test", "capabilities": {}},
            }) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
