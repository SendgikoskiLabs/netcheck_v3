#!/usr/bin/env python3
"""
SendgikoskiLabs NetCheck v3.1
==============================
A self-contained network diagnostic and monitoring tool.

Features:
  - DNS resolution timing
  - TCP connect latency
  - TLS handshake timing
  - HTTP/HTTPS status check
  - ASN / ISP / Geo lookup
  - Traceroute with slow-hop detection
  - Continuous monitor mode with:
      - Adaptive latency baseline + spike alerts
      - Packet loss detection
      - Subnet-aware IP change detection (suppresses anycast rotation noise)
      - ASN change detection
      - Route change detection
  - CLI interface (argparse subcommands)
  - GUI interface (tkinter, no installation required)
  - JSON output support
  - CSV logging

Changelog:
  v3.1 - Fixed Ctrl+C traceback in monitor mode (signal handler)
         Added subnet-aware IP change detection to suppress anycast noise

Requires: Python 3.8+, stdlib only EXCEPT 'requests' (pip install requests)
Run:
  python sendgikoski_netcheck.py                      # GUI
  python sendgikoski_netcheck.py ping google.com      # CLI ping
  python sendgikoski_netcheck.py check google.com     # full single-host check
  python sendgikoski_netcheck.py all                  # run all default hosts
  python sendgikoski_netcheck.py monitor              # continuous monitor (CLI)
  python sendgikoski_netcheck.py --help
"""

import subprocess
import socket
import ssl
import re
import sys
import csv
import json
import time
import signal
import platform
import statistics
import argparse
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict

# ─── Optional dependency ────────────────────────────────────────────────────
try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── Constants ──────────────────────────────────────────────────────────────
VERSION = "3.1"
TOOL_NAME = "SendgikoskiLabs NetCheck"

DEFAULT_HOSTS = [
    "google.com",
    "cloudflare.com",
    "github.com",
]

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"

LATENCY_SPIKE_MULTIPLIER = 2.0   # alert if avg > baseline * this
SPIKE_COOLDOWN = 300             # seconds between spike alerts per host
PACKET_LOSS_THRESHOLD = 20       # %
SLOW_HOP_THRESHOLD = 120         # ms
MONITOR_INTERVAL = 10            # seconds

OS = platform.system()
IS_WINDOWS = OS == "Windows"


# ─── Data classes ───────────────────────────────────────────────────────────

@dataclass
class PingResult:
    host: str
    packets_sent: int
    packets_received: int
    packet_loss: float
    min_time: float
    max_time: float
    avg_time: float
    std_dev: float
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class HostCheckResult:
    host: str
    ip: Optional[str]
    asn: str
    provider: str
    location: str
    dns_ms: Optional[float]
    tcp_ms: Optional[float]
    tls_ms: Optional[float]
    http_status: Optional[int]
    http_redirect: Optional[str]
    total_ms: float
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class TracerouteResult:
    host: str
    hops: List[Dict]
    filtered_hops: int
    slowest_hop: Optional[str]
    slowest_ms: float
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ─── Core diagnostics ───────────────────────────────────────────────────────

class NetDiag:
    """All network diagnostic primitives."""

    # ── Ping ────────────────────────────────────────────────────────────────

    @staticmethod
    def ping(host: str, count: int = 4, timeout: int = 4) -> PingResult:
        try:
            if IS_WINDOWS:
                cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout * count + 5
            )
            output = result.stdout
            packets_sent = count
            packets_received = 0
            times: List[float] = []

            if IS_WINDOWS:
                m = re.search(r"Received = (\d+)", output)
                if m:
                    packets_received = int(m.group(1))
                times = [float(t) for t in re.findall(r"time[<=](\d+)ms", output)]
            else:
                for line in output.splitlines():
                    m = re.search(r"time=(\d+\.?\d*)\s*ms", line)
                    if m:
                        times.append(float(m.group(1)))
                    m2 = re.search(r"(\d+) received", line)
                    if m2:
                        packets_received = int(m2.group(1))

            if packets_received == 0 or not times:
                return PingResult(host, packets_sent, 0, 100.0, 0, 0, 0, 0, False)

            loss = ((packets_sent - packets_received) / packets_sent) * 100
            return PingResult(
                host=host,
                packets_sent=packets_sent,
                packets_received=packets_received,
                packet_loss=round(loss, 2),
                min_time=round(min(times), 2),
                max_time=round(max(times), 2),
                avg_time=round(statistics.mean(times), 2),
                std_dev=round(statistics.stdev(times) if len(times) > 1 else 0.0, 2),
                success=True,
            )
        except subprocess.TimeoutExpired:
            return PingResult(host, count, 0, 100.0, 0, 0, 0, 0, False)
        except Exception as e:
            print(f"[ping error] {e}", file=sys.stderr)
            return PingResult(host, count, 0, 100.0, 0, 0, 0, 0, False)

    # ── DNS ─────────────────────────────────────────────────────────────────

    @staticmethod
    def dns_resolve(host: str):
        """Returns (ip, latency_ms) or (None, None)."""
        try:
            t0 = time.perf_counter()
            ip = socket.gethostbyname(host)
            ms = round((time.perf_counter() - t0) * 1000, 2)
            return ip, ms
        except Exception:
            return None, None

    # ── TCP connect ─────────────────────────────────────────────────────────

    @staticmethod
    def tcp_connect(host: str, port: int = 443, timeout: int = 3) -> Optional[float]:
        """Returns latency_ms or None on failure."""
        try:
            t0 = time.perf_counter()
            sock = socket.create_connection((host, port), timeout)
            sock.close()
            return round((time.perf_counter() - t0) * 1000, 2)
        except Exception:
            return None

    # ── TLS handshake ───────────────────────────────────────────────────────

    @staticmethod
    def tls_handshake(host: str, timeout: int = 5) -> Optional[float]:
        """Returns handshake latency_ms or None on failure."""
        try:
            ctx = ssl.create_default_context()
            t0 = time.perf_counter()
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
            return round((time.perf_counter() - t0) * 1000, 2)
        except Exception:
            return None

    # ── HTTP status ─────────────────────────────────────────────────────────

    @staticmethod
    def http_check(host: str):
        """Returns (status_code, redirect_url) or (None, None)."""
        if not HAS_REQUESTS:
            return None, None
        try:
            r = _requests.head(f"https://{host}", timeout=5, allow_redirects=False)
            return r.status_code, r.headers.get("Location")
        except Exception:
            return None, None

    # ── ASN / Geo ────────────────────────────────────────────────────────────

    @staticmethod
    def asn_lookup(ip: Optional[str]):
        """Returns (asn, provider, location) or ('Unknown', ...) on failure."""
        if not ip or not HAS_REQUESTS:
            return "Unknown", "Unknown", "Unknown"
        try:
            r = _requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            data = r.json()
            org = data.get("org", "Unknown")
            if org == "Unknown":
                return "Unknown", "Unknown", "Unknown"
            parts = org.split(None, 1)
            asn = parts[0]
            provider = parts[1] if len(parts) > 1 else "Unknown"
            location = ", ".join(
                filter(None, [data.get("city"), data.get("region"), data.get("country")])
            )
            return asn, provider, location
        except Exception:
            return "Unknown", "Unknown", "Unknown"

    # ── Traceroute ───────────────────────────────────────────────────────────

    @staticmethod
    def traceroute(host: str, max_hops: int = 15) -> TracerouteResult:
        try:
            if IS_WINDOWS:
                cmd = ["tracert", "-h", str(max_hops), host]
            else:
                cmd = ["traceroute", "-n", "-m", str(max_hops), host]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            output = result.stdout
            hops = []
            filtered_hops = 0
            slowest_hop = None
            slowest_ms = 0.0

            for line in output.splitlines()[1:]:
                if "* * *" in line:
                    filtered_hops += 1
                    continue
                parts = line.split()
                if not parts:
                    continue
                latencies = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", line)]
                hop_ip = None
                for p in parts:
                    if re.match(r"\d+\.\d+\.\d+\.\d+", p):
                        hop_ip = p
                        break
                hop = {
                    "hop": parts[0] if parts[0].isdigit() else "?",
                    "ip": hop_ip or "*",
                    "latencies": latencies,
                    "avg_ms": round(statistics.mean(latencies), 2) if latencies else None,
                }
                hops.append(hop)
                if latencies:
                    peak = max(latencies)
                    if peak > slowest_ms:
                        slowest_ms = peak
                        slowest_hop = line.strip()

            return TracerouteResult(
                host=host,
                hops=hops,
                filtered_hops=filtered_hops,
                slowest_hop=slowest_hop,
                slowest_ms=slowest_ms,
                success=bool(hops),
            )
        except Exception as e:
            return TracerouteResult(host, [], 0, None, 0.0, False)

    # ── Full host check ──────────────────────────────────────────────────────

    @classmethod
    def full_check(cls, host: str) -> HostCheckResult:
        t0 = time.perf_counter()
        ip, dns_ms = cls.dns_resolve(host)
        asn, provider, location = cls.asn_lookup(ip)
        tcp_ms = cls.tcp_connect(host)
        tls_ms = cls.tls_handshake(host)
        http_status, http_redirect = cls.http_check(host)
        total_ms = round((time.perf_counter() - t0) * 1000, 2)
        success = bool(ip and tcp_ms)
        return HostCheckResult(
            host=host,
            ip=ip,
            asn=asn,
            provider=provider,
            location=location,
            dns_ms=dns_ms,
            tcp_ms=tcp_ms,
            tls_ms=tls_ms,
            http_status=http_status,
            http_redirect=http_redirect,
            total_ms=total_ms,
            success=success,
        )


# ─── Subnet helpers ──────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    """Convert dotted-quad IPv4 string to integer."""
    try:
        parts = [int(x) for x in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except Exception:
        return 0


def _same_subnet(ip_a: str, ip_b: str, prefix: int = 24) -> bool:
    """
    Return True if two IPv4 addresses share the same /<prefix> subnet.
    Default /24 catches anycast rotation within a provider's address block
    (e.g. 140.82.112.x vs 140.82.114.x would NOT match at /24 but would
    at /16 — use prefix=16 for very broad suppression).
    """
    if not ip_a or not ip_b:
        return False
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return (_ip_to_int(ip_a) & mask) == (_ip_to_int(ip_b) & mask)


# ─── Monitor state ───────────────────────────────────────────────────────────

class MonitorState:
    """Holds per-host monitoring history and baselines."""

    def __init__(self):
        self.history: Dict[str, List[HostCheckResult]] = defaultdict(list)
        self.baseline: Dict[str, float] = {}
        self.last_ip: Dict[str, Optional[str]] = {}
        self.last_asn: Dict[str, Optional[str]] = {}
        self.last_route: Dict[str, List[str]] = {}
        self.last_spike: Dict[str, float] = {}

    def record(self, result: HostCheckResult):
        self.history[result.host].append(result)

    def analyze(self, host: str) -> Optional[dict]:
        samples = self.history[host]
        if len(samples) < 3:
            return None
        recent = samples[-5:]
        valid_tcp = [s.tcp_ms for s in recent if s.tcp_ms is not None and s.tcp_ms > 0]
        if not valid_tcp:
            return None
        failures = sum(1 for s in recent if s.tcp_ms is None or s.tcp_ms == 0)
        return {
            "avg": statistics.mean(valid_tcp),
            "min": min(valid_tcp),
            "max": max(valid_tcp),
            "jitter": max(valid_tcp) - min(valid_tcp),
            "loss": (failures / len(recent)) * 100,
        }

    def check_ip_change(self, host: str, new_ip: Optional[str],
                        anycast_prefix: int = 24) -> Optional[str]:
        """
        Detect meaningful IP changes, ignoring anycast rotation within the
        same /anycast_prefix subnet (default /24).
        Alert only when the IP crosses a subnet boundary (genuine re-route).
        """
        prev = self.last_ip.get(host)
        self.last_ip[host] = new_ip
        if not prev or not new_ip or prev == new_ip:
            return None
        if _same_subnet(prev, new_ip, anycast_prefix):
            return None  # Rotation within the same block — suppress
        return f"IP change: {prev} → {new_ip} (crossed /{anycast_prefix} boundary)"

    def check_asn_change(self, host: str, new_asn: str) -> Optional[str]:
        prev = self.last_asn.get(host)
        self.last_asn[host] = new_asn
        if prev and new_asn != "Unknown" and prev != new_asn:
            return f"ASN change: {prev} → {new_asn}"
        return None

    def check_route_change(self, host: str, new_route: List[str]) -> List[str]:
        prev = self.last_route.get(host)
        self.last_route[host] = new_route
        changes = []
        if prev and new_route and prev != new_route:
            for i, (old, new) in enumerate(zip(prev, new_route)):
                if old != new:
                    changes.append(f"Hop {i+1}: {old} → {new}")
        return changes


# ─── Formatters ──────────────────────────────────────────────────────────────

def _http_label(code: Optional[int]) -> str:
    if code is None:
        return "N/A"
    if 200 <= code < 300:
        return f"{code} [OK]"
    if 300 <= code < 400:
        return f"{code} [REDIRECT]"
    if 400 <= code < 500:
        return f"{code} [CLIENT ERROR]"
    if 500 <= code < 600:
        return f"{code} [SERVER ERROR]"
    return f"{code} [UNKNOWN]"


def format_ping(r: PingResult) -> str:
    status = "✓ Success" if r.success else "✗ Failed"
    return f"""
╔══════════════════════════════════════════════════════════╗
║         PING RESULTS  —  {status:<30}║
╚══════════════════════════════════════════════════════════╝
  Host             : {r.host}
  Packets Sent     : {r.packets_sent}
  Packets Received : {r.packets_received}
  Packet Loss      : {r.packet_loss:.1f}%
  Min / Avg / Max  : {r.min_time:.2f} / {r.avg_time:.2f} / {r.max_time:.2f} ms
  Std Dev (Jitter) : {r.std_dev:.2f} ms
  Timestamp        : {r.timestamp}
"""


def format_check(r: HostCheckResult) -> str:
    status = "✓ OK" if r.success else "✗ FAILED"
    tcp_str = f"{r.tcp_ms:.2f} ms  [OK]" if r.tcp_ms else "FAILED"
    tls_str = f"{r.tls_ms:.2f} ms" if r.tls_ms else "N/A"
    dns_str = f"{r.dns_ms:.2f} ms" if r.dns_ms else "N/A"
    return f"""
╔══════════════════════════════════════════════════════════╗
║      HOST CHECK  —  {status:<37}║
╚══════════════════════════════════════════════════════════╝
  Host             : {r.host}
  Resolved IP      : {r.ip or 'N/A'}
  ASN              : {r.asn}
  Provider         : {r.provider}
  Location         : {r.location}
  DNS Resolve      : {dns_str}
  TCP Connect      : {tcp_str}
  TLS Handshake    : {tls_str}
  HTTP Status      : {_http_label(r.http_status)}
  Redirect To      : {r.http_redirect or 'N/A'}
  Total Time       : {r.total_ms:.2f} ms
  Timestamp        : {r.timestamp}
"""


def format_traceroute(r: TracerouteResult) -> str:
    status = "✓ Success" if r.success else "✗ Failed"
    lines = [
        f"\n╔══════════════════════════════════════════════════════════╗",
        f"║   TRACEROUTE  —  {status:<40}║",
        f"╚══════════════════════════════════════════════════════════╝",
        f"  Host  : {r.host}",
        f"  Hops  : {len(r.hops)}   Filtered: {r.filtered_hops}",
        "",
        f"  {'HOP':<5} {'IP':<18} {'AVG ms':>8}",
        f"  {'─'*5} {'─'*18} {'─'*8}",
    ]
    for hop in r.hops:
        avg = f"{hop['avg_ms']:.2f}" if hop["avg_ms"] is not None else "  *"
        lines.append(f"  {hop['hop']:<5} {hop['ip']:<18} {avg:>8}")
    if r.filtered_hops:
        lines.append(f"\n  ⚠  {r.filtered_hops} hop(s) did not respond (filtered by ISP)")
    if r.slowest_hop and r.slowest_ms > SLOW_HOP_THRESHOLD:
        lines.append(f"\n  ⚠  Possible bottleneck detected at {r.slowest_ms:.1f} ms:")
        lines.append(f"     {r.slowest_hop}")
    lines.append(f"\n  Timestamp: {r.timestamp}")
    return "\n".join(lines)


# ─── CSV logging ─────────────────────────────────────────────────────────────

def _ensure_log_dir():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def log_check(r: HostCheckResult):
    _ensure_log_dir()
    log_file = LOG_DIR / "netcheck_log.csv"
    write_header = not log_file.exists()
    with open(log_file, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(["timestamp", "host", "ip", "dns_ms", "tcp_ms",
                        "tls_ms", "http_status", "total_ms"])
        w.writerow([
            r.timestamp, r.host, r.ip, r.dns_ms,
            r.tcp_ms, r.tls_ms, r.http_status, r.total_ms
        ])


# ─── Monitor loop (CLI) ──────────────────────────────────────────────────────

def monitor_cli(hosts: List[str], interval: int = MONITOR_INTERVAL):
    """Continuous monitoring loop with clean Ctrl+C shutdown via signal handler."""
    state = MonitorState()

    # ── Clean Ctrl+C handler — no traceback ─────────────────────────────────
    def _handle_sigint(sig, frame):
        print("\n\nMonitor stopped. Goodbye.\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    print(f"\n{TOOL_NAME} v{VERSION}  —  Monitor Mode")
    print(f"Hosts: {', '.join(hosts)}")
    print(f"Interval: {interval}s   (Ctrl+C to stop)\n")

    while True:
        for host in hosts:
            result = NetDiag.full_check(host)
            state.record(result)
            log_check(result)

            # ── Change detection ────────────────────────────────────────
            ip_alert = state.check_ip_change(host, result.ip)
            asn_alert = state.check_asn_change(host, result.asn)
            route = [h["ip"] for h in NetDiag.traceroute(host, max_hops=10).hops]
            route_changes = state.check_route_change(host, route)

            if ip_alert:
                print(f"\n⚠️  {host}: {ip_alert}")
            if asn_alert:
                print(f"\n🚨 {host}: {asn_alert}")
            for rc in route_changes:
                print(f"\n⚠️  {host} route change: {rc}")

            # ── Stats ───────────────────────────────────────────────────
            stats = state.analyze(host)
            if not stats:
                print(f"  {host:<22} — collecting samples…")
                continue

            avg = stats["avg"]

            # Latency spike
            if host not in state.baseline:
                state.baseline[host] = avg
            else:
                baseline = state.baseline[host]
                now = time.time()
                if avg > baseline * LATENCY_SPIKE_MULTIPLIER:
                    last_spike = state.last_spike.get(host, 0)
                    if now - last_spike > SPIKE_COOLDOWN:
                        print(f"\n⚠️  LATENCY SPIKE: {host}  avg={avg:.1f}ms  baseline={baseline:.1f}ms")
                        state.last_spike[host] = now
                # Exponential moving average
                state.baseline[host] = (baseline * 0.9) + (avg * 0.1)

            # Packet loss
            if stats["loss"] > PACKET_LOSS_THRESHOLD:
                print(f"\n🚨 PACKET LOSS: {host}  {stats['loss']:.0f}%")

            ts = datetime.now().strftime("%H:%M:%S")
            print(
                f"  [{ts}]  {host:<22}  "
                f"dns={result.dns_ms or '?':>6}ms  "
                f"tcp={result.tcp_ms or '?':>6}ms  "
                f"tls={result.tls_ms or '?':>6}ms  "
                f"http={_http_label(result.http_status)}"
            )

        print(f"\n{'─'*70}")
        time.sleep(interval)


# ─── CLI entry point ──────────────────────────────────────────────────────────

def build_cli():
    parser = argparse.ArgumentParser(
        prog="netcheck",
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sendgikoski_netcheck.py                         # launch GUI
  python sendgikoski_netcheck.py ping google.com         # ping
  python sendgikoski_netcheck.py ping google.com -c 10  # 10-packet ping
  python sendgikoski_netcheck.py check google.com        # full diagnostic
  python sendgikoski_netcheck.py traceroute google.com   # traceroute
  python sendgikoski_netcheck.py all                     # check all default hosts
  python sendgikoski_netcheck.py monitor                 # continuous monitor
  python sendgikoski_netcheck.py monitor --hosts github.com cloudflare.com
""",
    )

    subs = parser.add_subparsers(dest="command")

    # ping
    p = subs.add_parser("ping", help="Ping a host")
    p.add_argument("host")
    p.add_argument("-c", "--count", type=int, default=4)
    p.add_argument("-t", "--timeout", type=int, default=4)
    p.add_argument("-j", "--json", action="store_true")

    # check (full single-host)
    p = subs.add_parser("check", help="Full diagnostic for one host")
    p.add_argument("host")
    p.add_argument("-j", "--json", action="store_true")

    # traceroute
    p = subs.add_parser("traceroute", help="Traceroute to a host")
    p.add_argument("host")
    p.add_argument("-m", "--max-hops", type=int, default=15)
    p.add_argument("-j", "--json", action="store_true")

    # all
    p = subs.add_parser("all", help="Run full check on all default hosts")
    p.add_argument("-j", "--json", action="store_true")

    # monitor
    p = subs.add_parser("monitor", help="Continuous monitoring mode")
    p.add_argument(
        "--hosts", nargs="+", default=DEFAULT_HOSTS,
        metavar="HOST", help="Hosts to monitor (default: google.com cloudflare.com github.com)"
    )
    p.add_argument("-i", "--interval", type=int, default=MONITOR_INTERVAL)

    return parser


def run_cli(args):
    if not HAS_REQUESTS and args.command in ("check", "all", "monitor"):
        print("⚠  'requests' library not found. ASN/geo lookup and HTTP checks disabled.")
        print("   Install with: pip install requests\n")

    if args.command == "ping":
        r = NetDiag.ping(args.host, args.count, args.timeout)
        print(json.dumps(asdict(r), indent=2) if args.json else format_ping(r))

    elif args.command == "check":
        r = NetDiag.full_check(args.host)
        log_check(r)
        print(json.dumps(asdict(r), indent=2) if args.json else format_check(r))

    elif args.command == "traceroute":
        r = NetDiag.traceroute(args.host, args.max_hops)
        print(json.dumps(asdict(r), indent=2) if args.json else format_traceroute(r))

    elif args.command == "all":
        print(f"\n{TOOL_NAME} v{VERSION}  —  All Hosts\n{'═'*60}")
        t0 = time.time()
        for host in DEFAULT_HOSTS:
            r = NetDiag.full_check(host)
            log_check(r)
            if args.json:
                print(json.dumps(asdict(r), indent=2))
            else:
                print(format_check(r))
        print(f"Completed in {time.time() - t0:.2f}s\n")

    elif args.command == "monitor":
        monitor_cli(args.hosts, args.interval)


# ─── GUI ─────────────────────────────────────────────────────────────────────

def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, messagebox
    except ImportError:
        print("tkinter not available. Run a CLI command instead (--help for options).")
        sys.exit(1)

    if not HAS_REQUESTS:
        print("⚠  'requests' library not installed. ASN/geo/HTTP features will be limited in GUI.")

    root = tk.Tk()
    root.title(f"{TOOL_NAME} v{VERSION}")
    root.geometry("900x660")
    root.resizable(True, True)

    # ── Colour scheme ────────────────────────────────────────────────────────
    BG       = "#1e1e2e"
    FG       = "#cdd6f4"
    ACCENT   = "#89b4fa"
    GREEN    = "#a6e3a1"
    RED      = "#f38ba8"
    YELLOW   = "#f9e2af"
    ENTRY_BG = "#313244"
    BTN_BG   = "#45475a"

    root.configure(bg=BG)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TNotebook",        background=BG, borderwidth=0)
    style.configure("TNotebook.Tab",    background=BTN_BG, foreground=FG,
                    padding=[12, 4], font=("Courier", 10, "bold"))
    style.map("TNotebook.Tab",          background=[("selected", ACCENT)],
                                        foreground=[("selected", BG)])
    style.configure("TFrame",           background=BG)
    style.configure("TLabel",           background=BG, foreground=FG,
                    font=("Courier", 10))
    style.configure("TButton",          background=BTN_BG, foreground=FG,
                    font=("Courier", 10, "bold"), padding=6)
    style.map("TButton",                background=[("active", ACCENT)])
    style.configure("TEntry",           fieldbackground=ENTRY_BG, foreground=FG,
                    insertcolor=FG)
    style.configure("TCombobox",        fieldbackground=ENTRY_BG, foreground=FG,
                    background=ENTRY_BG)

    def make_output(parent) -> scrolledtext.ScrolledText:
        out = scrolledtext.ScrolledText(
            parent, bg=BG, fg=FG, font=("Courier", 10),
            insertbackground=FG, relief="flat", bd=0,
            wrap=tk.WORD
        )
        out.tag_config("ok",     foreground=GREEN)
        out.tag_config("warn",   foreground=YELLOW)
        out.tag_config("err",    foreground=RED)
        out.tag_config("accent", foreground=ACCENT)
        out.tag_config("head",   foreground=ACCENT, font=("Courier", 10, "bold"))
        return out

    def write(out: scrolledtext.ScrolledText, text: str, tag: str = ""):
        out.configure(state="normal")
        out.insert(tk.END, text, tag)
        out.see(tk.END)
        out.configure(state="disabled")

    def clear(out: scrolledtext.ScrolledText):
        out.configure(state="normal")
        out.delete("1.0", tk.END)
        out.configure(state="disabled")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=8, pady=8)

    # ── Tab helper ───────────────────────────────────────────────────────────
    def make_tab(label: str):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=f"  {label}  ")
        return frame

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — Ping
    # ════════════════════════════════════════════════════════════════════════
    tab_ping = make_tab("Ping")

    row0 = ttk.Frame(tab_ping); row0.pack(fill="x", padx=10, pady=8)
    ttk.Label(row0, text="Host:").pack(side="left")
    ping_host = ttk.Entry(row0, width=28); ping_host.insert(0, "google.com")
    ping_host.pack(side="left", padx=6)
    ttk.Label(row0, text="Count:").pack(side="left")
    ping_count = ttk.Entry(row0, width=5); ping_count.insert(0, "4")
    ping_count.pack(side="left", padx=4)

    ping_out = make_output(tab_ping)
    ping_out.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    def do_ping():
        host = ping_host.get().strip()
        count = int(ping_count.get().strip() or "4")
        if not host:
            return
        clear(ping_out)
        write(ping_out, f"Pinging {host} ({count} packets)…\n", "accent")
        root.update()

        def _run():
            r = NetDiag.ping(host, count)
            txt = format_ping(r)
            tag = "ok" if r.success else "err"
            root.after(0, lambda: write(ping_out, txt + "\n", tag))

        import threading; threading.Thread(target=_run, daemon=True).start()

    btn_row = ttk.Frame(tab_ping); btn_row.pack(pady=(0, 8))
    ttk.Button(btn_row, text="▶  Run Ping", command=do_ping).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", command=lambda: clear(ping_out)).pack(side="left")

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — Full Check
    # ════════════════════════════════════════════════════════════════════════
    tab_check = make_tab("Full Check")

    row0 = ttk.Frame(tab_check); row0.pack(fill="x", padx=10, pady=8)
    ttk.Label(row0, text="Host:").pack(side="left")
    check_host = ttk.Entry(row0, width=32); check_host.insert(0, "google.com")
    check_host.pack(side="left", padx=6)

    check_out = make_output(tab_check)
    check_out.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    def do_check():
        host = check_host.get().strip()
        if not host:
            return
        clear(check_out)
        write(check_out, f"Running full diagnostic for {host}…\n", "accent")
        root.update()

        def _run():
            r = NetDiag.full_check(host)
            log_check(r)
            txt = format_check(r)
            tag = "ok" if r.success else "err"
            root.after(0, lambda: write(check_out, txt + "\n", tag))

        import threading; threading.Thread(target=_run, daemon=True).start()

    btn_row = ttk.Frame(tab_check); btn_row.pack(pady=(0, 8))
    ttk.Button(btn_row, text="▶  Run Check", command=do_check).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", command=lambda: clear(check_out)).pack(side="left")

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — Traceroute
    # ════════════════════════════════════════════════════════════════════════
    tab_trace = make_tab("Traceroute")

    row0 = ttk.Frame(tab_trace); row0.pack(fill="x", padx=10, pady=8)
    ttk.Label(row0, text="Host:").pack(side="left")
    trace_host = ttk.Entry(row0, width=28); trace_host.insert(0, "google.com")
    trace_host.pack(side="left", padx=6)
    ttk.Label(row0, text="Max hops:").pack(side="left")
    trace_hops = ttk.Entry(row0, width=5); trace_hops.insert(0, "15")
    trace_hops.pack(side="left", padx=4)

    trace_out = make_output(tab_trace)
    trace_out.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    def do_trace():
        host = trace_host.get().strip()
        hops = int(trace_hops.get().strip() or "15")
        if not host:
            return
        clear(trace_out)
        write(trace_out, f"Tracing route to {host} (max {hops} hops)…\n", "accent")
        root.update()

        def _run():
            r = NetDiag.traceroute(host, hops)
            txt = format_traceroute(r)
            tag = "ok" if r.success else "warn"
            root.after(0, lambda: write(trace_out, txt + "\n", tag))

        import threading; threading.Thread(target=_run, daemon=True).start()

    btn_row = ttk.Frame(tab_trace); btn_row.pack(pady=(0, 8))
    ttk.Button(btn_row, text="▶  Run Traceroute", command=do_trace).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", command=lambda: clear(trace_out)).pack(side="left")

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 — Monitor
    # ════════════════════════════════════════════════════════════════════════
    tab_mon = make_tab("Monitor")

    row0 = ttk.Frame(tab_mon); row0.pack(fill="x", padx=10, pady=8)
    ttk.Label(row0, text="Hosts (comma-sep):").pack(side="left")
    mon_hosts_var = tk.StringVar(value=", ".join(DEFAULT_HOSTS))
    mon_hosts = ttk.Entry(row0, textvariable=mon_hosts_var, width=42)
    mon_hosts.pack(side="left", padx=6)
    ttk.Label(row0, text="Interval (s):").pack(side="left")
    mon_interval = ttk.Entry(row0, width=5); mon_interval.insert(0, str(MONITOR_INTERVAL))
    mon_interval.pack(side="left", padx=4)

    mon_out = make_output(tab_mon)
    mon_out.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    mon_running = [False]
    mon_state = [None]

    def mon_write(text: str, tag: str = ""):
        root.after(0, lambda: write(mon_out, text, tag))

    def do_monitor_tick(hosts, interval, state: MonitorState):
        if not mon_running[0]:
            return
        for host in hosts:
            result = NetDiag.full_check(host)
            state.record(result)
            log_check(result)

            ip_alert  = state.check_ip_change(host, result.ip)
            asn_alert = state.check_asn_change(host, result.asn)
            if ip_alert:
                mon_write(f"\n⚠️  {host}: {ip_alert}\n", "warn")
            if asn_alert:
                mon_write(f"\n🚨 {host}: {asn_alert}\n", "err")

            stats = state.analyze(host)
            ts = datetime.now().strftime("%H:%M:%S")
            if not stats:
                mon_write(f"  [{ts}]  {host:<22} — collecting…\n", "accent")
                continue

            avg = stats["avg"]
            if host not in state.baseline:
                state.baseline[host] = avg
            else:
                baseline = state.baseline[host]
                now = time.time()
                if avg > baseline * LATENCY_SPIKE_MULTIPLIER:
                    last = state.last_spike.get(host, 0)
                    if now - last > SPIKE_COOLDOWN:
                        mon_write(f"\n⚠️  LATENCY SPIKE: {host}  avg={avg:.1f}ms  baseline={baseline:.1f}ms\n", "warn")
                        state.last_spike[host] = now
                state.baseline[host] = (baseline * 0.9) + (avg * 0.1)

            if stats["loss"] > PACKET_LOSS_THRESHOLD:
                mon_write(f"\n🚨 PACKET LOSS: {host}  {stats['loss']:.0f}%\n", "err")

            tcp_str = f"{result.tcp_ms:.1f}ms" if result.tcp_ms else "FAIL"
            dns_str = f"{result.dns_ms:.1f}ms" if result.dns_ms else "N/A"
            http_str = str(result.http_status) if result.http_status else "N/A"
            line = (f"  [{ts}]  {host:<22}  dns={dns_str:<9}  "
                    f"tcp={tcp_str:<9}  http={http_str}\n")
            tag = "ok" if result.success else "err"
            mon_write(line, tag)

        mon_write(f"{'─'*65}\n", "accent")

        if mon_running[0]:
            root.after(interval * 1000, lambda: do_monitor_tick(hosts, interval, state))

    def start_monitor():
        if mon_running[0]:
            return
        hosts_raw = mon_hosts_var.get()
        hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]
        interval = int(mon_interval.get().strip() or str(MONITOR_INTERVAL))
        state = MonitorState()
        mon_state[0] = state
        mon_running[0] = True
        clear(mon_out)
        write(mon_out, f"{TOOL_NAME} v{VERSION} — Monitor\n", "head")
        write(mon_out, f"Hosts: {', '.join(hosts)}   Interval: {interval}s\n\n", "accent")

        import threading
        threading.Thread(
            target=lambda: do_monitor_tick(hosts, interval, state),
            daemon=True
        ).start()
        btn_start.config(state="disabled")
        btn_stop.config(state="normal")

    def stop_monitor():
        mon_running[0] = False
        mon_write("\n[Monitor stopped]\n", "warn")
        btn_start.config(state="normal")
        btn_stop.config(state="disabled")

    btn_row = ttk.Frame(tab_mon); btn_row.pack(pady=(0, 8))
    btn_start = ttk.Button(btn_row, text="▶  Start Monitor", command=start_monitor)
    btn_start.pack(side="left", padx=4)
    btn_stop  = ttk.Button(btn_row, text="■  Stop",          command=stop_monitor,
                           state="disabled")
    btn_stop.pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", command=lambda: clear(mon_out)).pack(side="left")

    # ════════════════════════════════════════════════════════════════════════
    # Status bar
    # ════════════════════════════════════════════════════════════════════════
    status_frame = tk.Frame(root, bg=BTN_BG, height=24)
    status_frame.pack(fill="x", side="bottom")
    req_status = "requests ✓" if HAS_REQUESTS else "requests ✗ (pip install requests)"
    tk.Label(
        status_frame,
        text=f"  {TOOL_NAME} v{VERSION}   |   Python {platform.python_version()}   |   {OS}   |   {req_status}",
        bg=BTN_BG, fg=FG, font=("Courier", 9), anchor="w"
    ).pack(fill="x", padx=6)

    root.mainloop()


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = build_cli()

    # If no CLI args → launch GUI
    if len(sys.argv) == 1:
        launch_gui()
        return

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    print(f"\n{TOOL_NAME} v{VERSION}\n{'═'*50}")
    run_cli(args)


if __name__ == "__main__":
    main()
