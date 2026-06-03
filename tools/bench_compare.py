#!/usr/bin/env python3
"""Compare benchmark results between two JSON files."""

import json
import sys


def load(path):
    with open(path) as f:
        data = json.load(f)
    benchmarks = {}
    for b in data.get("benchmarks", []):
        name = b["name"]
        real_time = b.get("real_time", 0)
        cpu_time = b.get("cpu_time", 0)
        bytes_per_sec = b.get("bytes_per_second", 0)
        items_per_sec = b.get("items_per_second", 0)
        iterations = b.get("iterations", 0)
        benchmarks[name] = {
            "real_time": real_time,
            "cpu_time": cpu_time,
            "bytes_per_sec": bytes_per_sec,
            "items_per_sec": items_per_sec,
            "iterations": iterations,
        }
    return benchmarks


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <new.json> [<old.json>]")
        print("\nIf only new.json is provided, prints all benchmarks.")
        print("If old.json is also provided, shows delta: +N% means slower.")
        return 1

    new_data = load(sys.argv[1])
    old_data = load(sys.argv[2]) if len(sys.argv) > 2 else {}

    print(f"{'Benchmark':<40} {'Real Time':<14} {'CPU Time':<14} {'Iterations':<12}")
    print("-" * 80)

    for name in sorted(new_data.keys()):
        n = new_data[name]
        rt = f"{n['real_time']:.2f} ns" if n['real_time'] < 1e6 else f"{n['real_time']/1e6:.2f} ms"
        ct = f"{n['cpu_time']:.2f} ns" if n['cpu_time'] < 1e6 else f"{n['cpu_time']/1e6:.2f} ms"

        if name in old_data:
            o = old_data[name]
            if o['real_time'] > 0:
                delta = ((n['real_time'] - o['real_time']) / o['real_time']) * 100
                rt += f" ({delta:+.1f}%)"
            if o['cpu_time'] > 0:
                delta = ((n['cpu_time'] - o['cpu_time']) / o['cpu_time']) * 100
                ct += f" ({delta:+.1f}%)"
        else:
            rt += " (NEW)"
            ct += " (NEW)"

        print(f"{name:<40} {rt:<14} {ct:<14} {n['iterations']:<12}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
