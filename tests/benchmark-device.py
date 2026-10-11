#!/usr/bin/env python3
"""Read-only, privacy-preserving LAN Speed device benchmark (Python 3.9+ stdlib).

Example:
  tests/benchmark-device.py root@192.0.2.1 --output /tmp/lanspeed-before.json

Only the listed read-only ubus methods and /proc counters are read. No reload,
configuration writes, installation, traffic generation, or raw client data is
performed/saved. Latencies include local ssh multiplexing and network overhead;
an empty-command baseline is reported separately, never subtracted implicitly.
Nonzero exit means an SSH/RPC/JSON/process-sampling check failed. Degraded
collector mode is reported as evidence rather than treated as a transport error.
"""

import argparse
import json
import math
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


METHODS = ("realtime", "status", "clients", "overview", "health", "diagnostics", "interfaces", "sysdevices")
SNAPSHOT = """set -eu
set -- $(pidof lanspeedd)
[ "$#" -eq 1 ]
pid=$1
printf 'PROCESS\\n'
cat /proc/$pid/stat
printf 'MEMORY\\n'
awk '/^VmRSS:|^VmSize:|^Threads:/ { print $1, $2 }' /proc/$pid/status
printf 'SYSTEM\\n'
awk '/^cpu/ { print }' /proc/stat
"""


class BenchmarkError(Exception):
    pass


def positive_int(value):
    number = int(value)
    if not 1 <= number <= 100:
        raise argparse.ArgumentTypeError("must be between 1 and 100")
    return number


def positive_seconds(value):
    number = float(value)
    if not math.isfinite(number) or not 0 < number <= 60:
        raise argparse.ArgumentTypeError("must be greater than 0 and at most 60 seconds")
    return number


def distribution(values):
    ordered = sorted(values)
    return {
        "min": round(ordered[0], 3),
        "median": round(statistics.median(ordered), 3),
        "p95": round(ordered[math.ceil(len(ordered) * .95) - 1], 3),
        "max": round(ordered[-1], 3),
    }


def summarize_payload(payload):
    """Allowlist metrics; never serialize arbitrary values from the device."""
    if not isinstance(payload, dict):
        raise BenchmarkError("RPC response is not a JSON object")
    if payload.get("error") or payload.get("errors"):
        raise BenchmarkError("RPC response reports an error")
    result = {}
    for key in ("clients", "interfaces", "devices", "connections"):
        if isinstance(payload.get(key), list):
            result[key + "_count"] = len(payload[key])
    if payload.get("mode") in ("Full", "Degraded", "Unavailable", "Disabled"):
        result["mode"] = payload["mode"]
    if payload.get("confidence") in ("high", "medium", "low", "none"):
        result["confidence"] = payload["confidence"]
    version = payload.get("version")
    if isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-r?[0-9]+)?", version):
        result["version"] = version
    warnings = payload.get("warnings")
    if isinstance(warnings, list):
        result["warning_count"] = len(warnings)
    evidence = payload.get("evidence")
    if isinstance(evidence, dict):
        for section, names in {
            "bpf": ("attached_hook_count", "expected_hook_count", "object_loaded"),
            "probe_failures": ("total", "truncated"),
        }.items():
            source = evidence.get(section)
            if isinstance(source, dict):
                result[section] = {key: source[key] for key in names
                                   if isinstance(source.get(key), (int, bool))}
    return result


def parse_snapshot(raw):
    try:
        process, remainder = raw.split("MEMORY\n", 1)
        memory, system = remainder.split("SYSTEM\n", 1)
        process = process.removeprefix("PROCESS\n").strip()
        pid = int(process.split(" ", 1)[0])
        fields = process.rsplit(")", 1)[1].split()
        cpu_lines = system.splitlines()
        # /proc/stat guest and guest_nice are already included in user/nice.
        total_ticks = sum(map(int, cpu_lines[0].split()[1:9]))
        values = dict(line.split() for line in memory.splitlines())
        return {
            "pid": pid,
            "start_ticks": int(fields[19]),
            "process_ticks": int(fields[11]) + int(fields[12]),
            "system_ticks": total_ticks,
            "cpu_count": len(cpu_lines) - 1,
            "rss_kib": int(values["VmRSS:"]),
            "virtual_kib": int(values["VmSize:"]),
            "threads": int(values["Threads:"]),
        }
    except (ValueError, KeyError, IndexError):
        raise BenchmarkError("invalid or incomplete /proc snapshot") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="SSH host or user@host, with existing key authentication")
    parser.add_argument("--samples", type=positive_int, default=5)
    parser.add_argument("--timeout", type=positive_seconds, default=15, help="per-command timeout in seconds (default: 15)")
    parser.add_argument("--cpu-window", type=positive_seconds, default=5, help="minimum sampling window in seconds (default: 5)")
    parser.add_argument("--ssh-option", action="append", default=[], help="ssh -o option; repeat as needed")
    parser.add_argument("--output", type=Path, help="write sanitized JSON with mode 0600; default: stdout")
    args = parser.parse_args()
    if args.target.startswith("-") or any(c.isspace() for c in args.target):
        parser.error("target must be an SSH hostname or user@hostname")

    report = {
        "schema": "lanspeed.device-benchmark.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "latency_scope": "ssh_multiplexed_round_trip_including_network_and_process_overhead",
        "cpu_scope": "daemon_during_read_only_rpc_benchmark",
        "samples": args.samples,
        "methods": {},
        "errors": [],
    }
    with tempfile.TemporaryDirectory(prefix="lanspeed-benchmark-") as directory:
        ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
        for option in args.ssh_option:
            ssh.extend(["-o", option])
        # A dedicated master avoids borrowing or closing the user's SSH session.
        ssh.extend(["-o", "ControlMaster=auto", "-o", "ControlPersist=30",
                    "-o", "ControlPath=" + directory + "/ssh"])

        def run(command):
            started = time.perf_counter()
            try:
                response = subprocess.run(ssh + ["--", args.target, command],
                                          stdin=subprocess.DEVNULL, capture_output=True,
                                          timeout=args.timeout)
            except subprocess.TimeoutExpired:
                raise BenchmarkError("command timed out") from None
            except OSError:
                raise BenchmarkError("unable to execute ssh") from None
            elapsed = (time.perf_counter() - started) * 1000
            if response.returncode:
                # stderr may contain client addresses or device data.
                raise BenchmarkError("SSH/RPC command exited with code " + str(response.returncode))
            return response.stdout, elapsed

        try:
            run("true")  # Connect before recording multiplexed samples.
            report["ssh_overhead_ms"] = distribution([run("true")[1] for _ in range(args.samples)])
            before = parse_snapshot(run(SNAPSHOT)[0].decode())
            window_start = time.perf_counter()
            for method in METHODS:
                latencies, sizes, summaries = [], [], []
                try:
                    for _ in range(args.samples):
                        raw, latency = run("ubus call lanspeed " + method)
                        try:
                            payload = json.loads(raw)
                        except (ValueError, UnicodeError):
                            raise BenchmarkError("RPC returned invalid JSON") from None
                        summaries.append(summarize_payload(payload))
                        latencies.append(latency)
                        sizes.append(len(raw))
                    report["methods"][method] = {
                        "latency_ms": distribution(latencies),
                        "response_bytes": distribution(sizes),
                        "last_summary": summaries[-1],
                    }
                except BenchmarkError as error:
                    report["errors"].append({"stage": method, "reason": str(error)})
            remaining = args.cpu_window - (time.perf_counter() - window_start)
            if remaining > 0:
                time.sleep(remaining)
            after = parse_snapshot(run(SNAPSHOT)[0].decode())
            if (before["pid"], before["start_ticks"]) != (after["pid"], after["start_ticks"]):
                raise BenchmarkError("daemon restarted during benchmark")
            system_delta = after["system_ticks"] - before["system_ticks"]
            process_delta = after["process_ticks"] - before["process_ticks"]
            if system_delta <= 0 or process_delta < 0 or before["cpu_count"] != after["cpu_count"]:
                raise BenchmarkError("CPU counters changed inconsistently")
            report["process"] = {
                "window_seconds": round(time.perf_counter() - window_start, 3),
                "cpu_percent_one_core": round(process_delta / system_delta * after["cpu_count"] * 100, 3),
                "cpu_count": after["cpu_count"],
                "rss_before_kib": before["rss_kib"],
                "rss_after_kib": after["rss_kib"],
                "rss_delta_kib": after["rss_kib"] - before["rss_kib"],
                "threads": after["threads"],
            }
        except (BenchmarkError, UnicodeError) as error:
            report["errors"].append({"stage": "benchmark", "reason": str(error) if isinstance(error, BenchmarkError) else "invalid /proc encoding"})
        finally:
            try:
                subprocess.run(ssh + ["-O", "exit", "--", args.target],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass

    report["ok"] = not report["errors"]
    rendered = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    if args.output:
        # Atomic replacement avoids partial baseline files; temp files are 0600.
        with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as output:
            temporary = output.name
            try:
                output.write(rendered)
                output.close()
                os.replace(temporary, args.output)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        print("Sanitized device benchmark: " + str(args.output))
    else:
        print(rendered, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
