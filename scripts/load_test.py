#!/usr/bin/env python3
"""Real concurrent load test, matched to this architecture's ACTUAL
concurrency model: one warden-proxy process per agent session (like an
MCP server), not a multi-tenant network server. So "concurrent load"
here means what it actually means in production: many agent sessions
running at once, each with its own Warden process, all hammering their
fast path (READ_ONLY, no quorum) simultaneously.

Measures aggregate throughput (total calls / wall-clock duration across
all concurrent processes) and global latency percentiles.

Usage: python3 scripts/load_test.py [--processes N] [--calls-per-process K]
       [--binary path/to/warden-proxy]

Run against a Release build (no sanitizers) for a real performance
number -- sanitizers add real overhead that would make the number
dishonest as a performance claim. See NOTES.md for the measured results
and what they do/don't mean.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FAKE_SERVER = os.path.join(REPO_ROOT, "scripts", "fake_mcp_server.py")


def run_one_process(binary, calls, results, idx, latencies_lock, all_latencies):
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "downstream_command": ["python3", FAKE_SERVER],
            "audit_log": os.path.join(tmpdir, "audit.log"),
            "tools": {"fetch_url": {"ingests_untrusted": True, "risk_class": "READ_ONLY"}},
        }
        cfg_path = os.path.join(tmpdir, "cfg.json")
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)

        proc = subprocess.Popen([binary, cfg_path], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, bufsize=1, cwd=REPO_ROOT)
        local_latencies = []
        for i in range(calls):
            req = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                   "params": {"name": "fetch_url", "arguments": {"url": "https://example.com/clean"}}}
            start = time.perf_counter()
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
            proc.stdout.readline()
            elapsed_ms = (time.perf_counter() - start) * 1000
            # First call of each process bundles process-spawn + the
            # downstream Python subprocess's own spawn time -- with many
            # processes starting at once that's real OS scheduling
            # contention, not Warden's own per-call overhead. Tagged
            # separately so it doesn't dominate the number that actually
            # matters (same reasoning as the sequential benchmark in
            # scripts/benchmark/runner.py).
            local_latencies.append({"ms": elapsed_ms, "cold_start": i == 0})

        proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

        with latencies_lock:
            all_latencies.extend(local_latencies)
        results[idx] = len(local_latencies)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--processes", type=int, default=50)
    parser.add_argument("--calls-per-process", type=int, default=100)
    parser.add_argument("--binary", default=os.path.join(REPO_ROOT, "build-release", "warden-proxy"))
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"binary not found at {args.binary} -- build a Release config first:\n"
              f"  cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release\n"
              f"  cmake --build build-release -j", file=sys.stderr)
        sys.exit(1)

    results = [0] * args.processes
    all_latencies = []
    latencies_lock = threading.Lock()
    threads = []

    print(f"starting {args.processes} concurrent warden-proxy processes, "
          f"{args.calls_per_process} calls each ({args.processes * args.calls_per_process} total)...")

    start = time.perf_counter()
    for i in range(args.processes):
        t = threading.Thread(target=run_one_process,
                              args=(args.binary, args.calls_per_process, results, i,
                                    latencies_lock, all_latencies))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    total_wall_s = time.perf_counter() - start

    total_calls = sum(results)

    def pct(values, p):
        s = sorted(values)
        return s[min(int(len(s) * p), len(s) - 1)]

    warm = [x["ms"] for x in all_latencies if not x["cold_start"]]
    cold = [x["ms"] for x in all_latencies if x["cold_start"]]

    print(f"\ntotal calls completed: {total_calls} across {args.processes} concurrent processes")
    print(f"wall-clock duration: {total_wall_s:.3f}s")
    print(f"aggregate throughput: {total_calls / total_wall_s:.0f} calls/sec "
          f"(sum across {args.processes} concurrent processes)")
    if warm:
        print(f"steady-state latency under concurrent load (N={len(warm)}): "
              f"p50={pct(warm,0.50):.3f}ms p95={pct(warm,0.95):.3f}ms "
              f"p99={pct(warm,0.99):.3f}ms max={max(warm):.3f}ms")
    if cold:
        print(f"cold-start/first-call under concurrent spawn contention (N={len(cold)}): "
              f"p50={pct(cold,0.50):.3f}ms max={max(cold):.3f}ms")


if __name__ == "__main__":
    main()
