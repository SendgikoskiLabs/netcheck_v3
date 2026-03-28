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
  v3.5 - Fixed Windows traceroute: added -w 2000 flag to reduce per-hop wait,
         fixed encoding to cp850 to prevent silent UnicodeDecodeError,
         success now true when filtered hops exist even with no visible hops
  v3.4 - Fixed Windows traceroute: split parser into OS-specific methods,
         handle 'Request timed out.' hops, correct IP position parsing,
         fix header line skip, increase per-hop timeout
  v3.3 - Redesigned GUI: tabbed toolbar layout, Export buttons, Enter-key shortcuts,
         live host status indicators, dynamic status bar, About tab
  v3.2 - Fixed negative elapsed time in 'all' command
         Added NAT/firewall/WSL2 path-obscuration warning in traceroute results

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
VERSION = "3.5"
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
    nat_warning: bool = False          # True when path appears obscured by NAT/firewall
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
                # -h = max hops, -w 2000 = wait 2000ms per hop (default is 4000ms)
                # Reducing -w speeds up traces through filtered hops significantly
                cmd = ["tracert", "-h", str(max_hops), "-w", "2000", host]
                # Budget: 2s per hop × max_hops + 30s buffer
                timeout = max_hops * 2 + 30
                # Windows tracert outputs in the system codepage (cp850/cp1252)
                # Using errors='replace' prevents UnicodeDecodeError on non-ASCII
                encoding = "cp850"
            else:
                cmd = ["traceroute", "-n", "-m", str(max_hops), host]
                timeout = max_hops * 5 + 10
                encoding = "utf-8"

            result = subprocess.run(
                cmd, capture_output=True, timeout=timeout,
                encoding=encoding, errors="replace"
            )
            output = result.stdout
            stderr  = result.stderr

            # Surface any error from stderr or empty output
            if not output.strip():
                err_msg = stderr.strip() if stderr and stderr.strip() else \
                    f"Command produced no output (exit code {result.returncode})"
                return TracerouteResult(
                    host=host, hops=[], filtered_hops=0,
                    slowest_hop=err_msg, slowest_ms=0.0,
                    success=False, nat_warning=False
                )

            if IS_WINDOWS:
                hops, filtered_hops, slowest_hop, slowest_ms = \
                    NetDiag._parse_tracert_windows(output)
            else:
                hops, filtered_hops, slowest_hop, slowest_ms = \
                    NetDiag._parse_traceroute_linux(output)

            # ── NAT / firewall / WSL2 path obscuration detection ────────
            nat_warning = (len(hops) <= 2 and filtered_hops >= 3)

            return TracerouteResult(
                host=host,
                hops=hops,
                filtered_hops=filtered_hops,
                slowest_hop=slowest_hop,
                slowest_ms=slowest_ms,
                success=bool(hops) or filtered_hops > 0,
                nat_warning=nat_warning,
            )
        except subprocess.TimeoutExpired:
            return TracerouteResult(
                host=host, hops=[], filtered_hops=0,
                slowest_hop=f"Timed out after {timeout}s — try reducing max hops",
                slowest_ms=0.0, success=False, nat_warning=False
            )
        except FileNotFoundError:
            cmd_name = "tracert" if IS_WINDOWS else "traceroute"
            return TracerouteResult(
                host=host, hops=[], filtered_hops=0,
                slowest_hop=f"'{cmd_name}' not found — is it on PATH?",
                slowest_ms=0.0, success=False, nat_warning=False
            )
        except Exception as e:
            return TracerouteResult(
                host=host, hops=[], filtered_hops=0,
                slowest_hop=f"Error: {type(e).__name__}: {e}",
                slowest_ms=0.0, success=False, nat_warning=False
            )

    @staticmethod
    def _parse_tracert_windows(output: str):
        """
        Parse Windows tracert output.

        Windows tracert format:
          Tracing route to google.com [64.233.177.138]
          over a maximum of 5 hops:

            1     4 ms     4 ms     3 ms  172.19.54.193
            2     *        *        *     Request timed out.
            3    12 ms    11 ms    10 ms  192.168.1.1

          Trace complete.

        Key differences from Linux traceroute:
          - Two header lines before hop data
          - Latencies formatted as "4 ms" (space before ms)
          - Timed-out hops: "Request timed out." (not "* * *")
          - IP address appears AFTER latencies
          - Lines are indented
          - Some hops show mixed: "4 ms  *  4 ms  192.168.1.1"
        """
        hops = []
        filtered_hops = 0
        slowest_hop = None
        slowest_ms = 0.0

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Strictly require the line to begin with a hop number (1-999)
            # This reliably skips all header, footer, and blank lines
            parts = stripped.split()
            if not parts:
                continue
            try:
                hop_num = int(parts[0])
            except ValueError:
                continue  # Not a hop line — skip header/footer

            hop_num_str = str(hop_num)

            # Timed-out hop — counts as filtered, not as a visible hop
            if "timed out" in stripped.lower():
                filtered_hops += 1
                continue

            # Extract latencies — Windows: "4 ms" with space before ms
            # Use \s+ to require at least one space (avoids matching "4ms" edge cases)
            latencies = [
                float(x)
                for x in re.findall(r"(\d+(?:\.\d+)?)\s+ms", stripped)
            ]

            # Extract IP — always the last IPv4 address on the line
            hop_ip = None
            ip_matches = re.findall(
                r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", stripped
            )
            if ip_matches:
                hop_ip = ip_matches[-1]

            # Pure star hop (no latency, no IP) — count as filtered
            if not latencies and not hop_ip:
                filtered_hops += 1
                continue

            avg = round(statistics.mean(latencies), 2) if latencies else None
            hop = {
                "hop": hop_num_str,
                "ip": hop_ip or "*",
                "latencies": latencies,
                "avg_ms": avg,
            }
            hops.append(hop)

            if latencies:
                peak = max(latencies)
                if peak > slowest_ms:
                    slowest_ms = peak
                    slowest_hop = stripped

        return hops, filtered_hops, slowest_hop, slowest_ms

    @staticmethod
    def _parse_traceroute_linux(output: str):
        """
        Parse Linux/macOS traceroute output.

        Linux traceroute -n format:
          traceroute to google.com (...), 15 hops max, 60 byte packets
           1  172.28.128.1  0.470 ms  0.437 ms  0.421 ms
           2  172.19.54.193  7.042 ms  7.023 ms  6.993 ms
           3  * * *

        Key differences from Windows tracert:
          - Single header line
          - IP appears before latencies
          - Filtered hops shown as "* * *"
          - No "ms" space issue (uses "0.470 ms")
        """
        hops = []
        filtered_hops = 0
        slowest_hop = None
        slowest_ms = 0.0

        for line in output.splitlines()[1:]:  # skip first header line
            stripped = line.strip()
            if not stripped:
                continue

            parts = stripped.split()
            if not parts:
                continue

            # Filtered hop
            if "* * *" in stripped:
                filtered_hops += 1
                continue

            # Must start with a hop number
            if not parts[0].isdigit():
                continue

            hop_num = parts[0]

            # Extract latencies
            latencies = [
                float(x)
                for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", stripped)
            ]

            # Extract IP — on Linux it appears right after the hop number
            hop_ip = None
            for p in parts[1:]:
                if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", p):
                    hop_ip = p
                    break

            avg = round(statistics.mean(latencies), 2) if latencies else None
            hop = {
                "hop": hop_num,
                "ip": hop_ip or "*",
                "latencies": latencies,
                "avg_ms": avg,
            }
            hops.append(hop)

            if latencies:
                peak = max(latencies)
                if peak > slowest_ms:
                    slowest_ms = peak
                    slowest_hop = stripped

        return hops, filtered_hops, slowest_hop, slowest_ms

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
    ]
    # Show error detail when the command failed outright
    if not r.success and r.slowest_hop and not r.hops:
        lines.append(f"\n  ✗  Error: {r.slowest_hop}")
        lines.append(f"\n  Timestamp: {r.timestamp}")
        return "\n".join(lines)
    lines += [
        "",
        f"  {'HOP':<5} {'IP':<18} {'AVG ms':>8}",
        f"  {'─'*5} {'─'*18} {'─'*8}",
    ]
    for hop in r.hops:
        avg = f"{hop['avg_ms']:.2f}" if hop["avg_ms"] is not None else "  *"
        lines.append(f"  {hop['hop']:<5} {hop['ip']:<18} {avg:>8}")
    if r.filtered_hops:
        lines.append(f"\n  ⚠  {r.filtered_hops} hop(s) did not respond (filtered by ISP)")
    if r.nat_warning:
        lines.append(f"\n  ╔══════════════════════════════════════════════════════╗")
        lines.append(f"  ║  ⚠  PATH OBSCURATION WARNING                        ║")
        lines.append(f"  ╠══════════════════════════════════════════════════════╣")
        lines.append(f"  ║  Only {len(r.hops)} hop(s) visible before the path goes dark.  ║")
        lines.append(f"  ║  This typically means one or more of the following:  ║")
        lines.append(f"  ║    • Running inside WSL2 / Hyper-V / a VM            ║")
        lines.append(f"  ║    • Double-NAT (router behind router)               ║")
        lines.append(f"  ║    • ISP or corporate firewall blocking all probes   ║")
        lines.append(f"  ║  Traceroute results beyond hop {len(r.hops)} are unreliable.  ║")
        lines.append(f"  ║  For accurate path data, run from a bare-metal host  ║")
        lines.append(f"  ║  or a cloud VPS with direct internet routing.        ║")
        lines.append(f"  ╚══════════════════════════════════════════════════════╝")
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
        t0 = time.time()
        print(f"\n{TOOL_NAME} v{VERSION}  —  All Hosts\n{'═'*60}")
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
        from tkinter import ttk, scrolledtext, messagebox, filedialog
    except ImportError:
        print("tkinter not available. Run a CLI command instead (--help for options).")
        sys.exit(1)

    if not HAS_REQUESTS:
        print("⚠  'requests' library not installed. ASN/geo/HTTP features will be limited in GUI.")

    # ── Window setup ─────────────────────────────────────────────────────────
    root = tk.Tk()
    root.title(f"{TOOL_NAME} v{VERSION}")
    root.geometry("960x700")
    root.minsize(800, 560)
    root.resizable(True, True)

    # ── Colour palette (Catppuccin Mocha) ────────────────────────────────────
    BG       = "#1e1e2e"   # base
    BG2      = "#181825"   # mantle (slightly darker, for panels)
    FG       = "#cdd6f4"   # text
    SUBTLE   = "#6c7086"   # overlay0  (dimmed text)
    ACCENT   = "#89b4fa"   # blue
    GREEN    = "#a6e3a1"   # green
    RED      = "#f38ba8"   # red
    YELLOW   = "#f9e2af"   # yellow
    MAUVE    = "#cba6f7"   # mauve  (used for branding / headings)
    ENTRY_BG = "#313244"   # surface0
    BTN_BG   = "#45475a"   # surface1
    SEP      = "#585b70"   # surface2 (separator lines)

    root.configure(bg=BG)

    # ── ttk styles ───────────────────────────────────────────────────────────
    style = ttk.Style()
    style.theme_use("clam")

    style.configure("TNotebook",
                    background=BG, borderwidth=0, tabmargins=[0, 0, 0, 0])
    style.configure("TNotebook.Tab",
                    background=BTN_BG, foreground=FG,
                    padding=[14, 5], font=("Courier", 10, "bold"))
    style.map("TNotebook.Tab",
              background=[("selected", ACCENT)],
              foreground=[("selected", BG)])

    style.configure("TFrame",  background=BG)
    style.configure("TLabel",  background=BG, foreground=FG, font=("Courier", 10))
    style.configure("Subtle.TLabel", background=BG, foreground=SUBTLE,
                    font=("Courier", 9))
    style.configure("Heading.TLabel", background=BG, foreground=MAUVE,
                    font=("Courier", 11, "bold"))

    style.configure("TButton",
                    background=BTN_BG, foreground=FG,
                    font=("Courier", 10, "bold"), padding=[8, 5], relief="flat")
    style.map("TButton",
              background=[("active", ACCENT), ("disabled", BG2)],
              foreground=[("active", BG),     ("disabled", SUBTLE)])

    style.configure("Accent.TButton",
                    background=ACCENT, foreground=BG,
                    font=("Courier", 10, "bold"), padding=[8, 5], relief="flat")
    style.map("Accent.TButton",
              background=[("active", MAUVE)])

    style.configure("TEntry",
                    fieldbackground=ENTRY_BG, foreground=FG,
                    insertcolor=FG, relief="flat", padding=4)
    style.configure("TCombobox",
                    fieldbackground=ENTRY_BG, foreground=FG,
                    background=ENTRY_BG)
    style.configure("TSeparator", background=SEP)

    # ── Shared helpers ───────────────────────────────────────────────────────

    def make_output(parent) -> scrolledtext.ScrolledText:
        out = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=FG, font=("Courier", 10),
            insertbackground=FG, relief="flat", bd=0,
            wrap=tk.WORD, padx=8, pady=6,
            selectbackground=ACCENT, selectforeground=BG,
        )
        out.tag_config("ok",      foreground=GREEN)
        out.tag_config("warn",    foreground=YELLOW)
        out.tag_config("err",     foreground=RED)
        out.tag_config("accent",  foreground=ACCENT)
        out.tag_config("mauve",   foreground=MAUVE)
        out.tag_config("subtle",  foreground=SUBTLE)
        out.tag_config("head",    foreground=MAUVE,  font=("Courier", 11, "bold"))
        out.tag_config("subhead", foreground=ACCENT, font=("Courier", 10, "bold"))
        return out

    def w(out: scrolledtext.ScrolledText, text: str, tag: str = ""):
        """Append text to an output widget."""
        out.configure(state="normal")
        out.insert(tk.END, text, tag)
        out.see(tk.END)
        out.configure(state="disabled")

    def clear_out(out: scrolledtext.ScrolledText):
        out.configure(state="normal")
        out.delete("1.0", tk.END)
        out.configure(state="disabled")

    def export_output(out: scrolledtext.ScrolledText, default_name: str):
        """Save the contents of an output widget to a text file."""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            content = out.get("1.0", tk.END)
            Path(path).write_text(content)
            set_status(f"Exported → {path}")

    # ── Status bar (persistent, bottom of window) ────────────────────────────
    status_bar = tk.Frame(root, bg=BTN_BG, height=26)
    status_bar.pack(fill="x", side="bottom")
    status_bar.pack_propagate(False)

    status_left = tk.Label(
        status_bar,
        text=f"  {TOOL_NAME} v{VERSION}   |   Python {platform.python_version()}   |   {OS}",
        bg=BTN_BG, fg=FG, font=("Courier", 9), anchor="w",
    )
    status_left.pack(side="left", fill="x", expand=True, padx=6)

    req_indicator = "● requests" if HAS_REQUESTS else "○ requests (pip install requests)"
    req_color = GREEN if HAS_REQUESTS else YELLOW
    status_right = tk.Label(
        status_bar,
        text=f"{req_indicator}  ",
        bg=BTN_BG, fg=req_color, font=("Courier", 9), anchor="e",
    )
    status_right.pack(side="right", padx=6)

    def set_status(msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        status_left.config(
            text=f"  [{ts}]  {msg}"
        )

    # ── Toolbar helper ───────────────────────────────────────────────────────
    def make_toolbar(parent) -> tk.Frame:
        bar = tk.Frame(parent, bg=BG2, pady=6)
        bar.pack(fill="x", side="top")
        return bar

    def make_content(parent) -> tk.Frame:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        return frame

    def toolbar_label(bar, text):
        tk.Label(bar, text=text, bg=BG2, fg=FG,
                 font=("Courier", 10)).pack(side="left", padx=(10, 2))

    def toolbar_entry(bar, width, default=""):
        e = ttk.Entry(bar, width=width)
        e.insert(0, default)
        e.pack(side="left", padx=(0, 8))
        return e

    def toolbar_sep(bar):
        tk.Frame(bar, bg=SEP, width=1).pack(side="left", fill="y",
                                             padx=6, pady=4)

    # ── Notebook ─────────────────────────────────────────────────────────────
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=6, pady=(6, 0))

    def make_tab(label: str) -> ttk.Frame:
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=f"  {label}  ")
        return frame

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — Ping
    # ════════════════════════════════════════════════════════════════════════
    tab_ping = make_tab("🔵  Ping")
    tb1 = make_toolbar(tab_ping)

    toolbar_label(tb1, "Host:")
    ping_host = toolbar_entry(tb1, 26, "google.com")
    toolbar_label(tb1, "Count:")
    ping_count = toolbar_entry(tb1, 4, "4")
    toolbar_sep(tb1)

    ping_out = make_output(make_content(tab_ping))
    ping_out.pack(fill="both", expand=True)

    def do_ping(*_):
        host  = ping_host.get().strip()
        try:
            count = int(ping_count.get().strip() or "4")
        except ValueError:
            count = 4
        if not host:
            return
        clear_out(ping_out)
        w(ping_out, f"Pinging {host}  ({count} packets)…\n\n", "accent")
        set_status(f"Pinging {host}…")

        def _run():
            r   = NetDiag.ping(host, count)
            txt = format_ping(r)
            tag = "ok" if r.success else "err"
            root.after(0, lambda: w(ping_out, txt + "\n", tag))
            root.after(0, lambda: set_status(
                f"Ping {host} — {'OK' if r.success else 'FAILED'}  "
                f"avg={r.avg_time:.1f}ms  loss={r.packet_loss:.0f}%"
            ))

        import threading
        threading.Thread(target=_run, daemon=True).start()

    ping_run_btn = ttk.Button(tb1, text="▶  Run", style="Accent.TButton",
                              command=do_ping)
    ping_run_btn.pack(side="left", padx=2)
    ttk.Button(tb1, text="Clear",
               command=lambda: clear_out(ping_out)).pack(side="left", padx=2)
    ttk.Button(tb1, text="Export",
               command=lambda: export_output(
                   ping_out, f"ping_{ping_host.get().strip()}.txt"
               )).pack(side="left", padx=2)

    ping_host.bind("<Return>", do_ping)
    ping_count.bind("<Return>", do_ping)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — Full Check
    # ════════════════════════════════════════════════════════════════════════
    tab_check = make_tab("🔍  Full Check")
    tb2 = make_toolbar(tab_check)

    toolbar_label(tb2, "Host:")
    check_host = toolbar_entry(tb2, 30, "google.com")
    toolbar_sep(tb2)

    check_out = make_output(make_content(tab_check))
    check_out.pack(fill="both", expand=True)

    def do_check(*_):
        host = check_host.get().strip()
        if not host:
            return
        clear_out(check_out)
        w(check_out, f"Running full diagnostic for {host}…\n\n", "accent")
        set_status(f"Checking {host}…")

        def _run():
            r   = NetDiag.full_check(host)
            log_check(r)
            txt = format_check(r)
            tag = "ok" if r.success else "err"
            root.after(0, lambda: w(check_out, txt + "\n", tag))
            root.after(0, lambda: set_status(
                f"Check {host} — {'OK' if r.success else 'FAILED'}  "
                f"tcp={r.tcp_ms:.1f}ms  tls={r.tls_ms:.1f}ms  "
                f"http={r.http_status}"
                if r.tcp_ms and r.tls_ms and r.http_status
                else f"Check {host} — FAILED"
            ))

        import threading
        threading.Thread(target=_run, daemon=True).start()

    ttk.Button(tb2, text="▶  Run", style="Accent.TButton",
               command=do_check).pack(side="left", padx=2)
    ttk.Button(tb2, text="Clear",
               command=lambda: clear_out(check_out)).pack(side="left", padx=2)
    ttk.Button(tb2, text="Export",
               command=lambda: export_output(
                   check_out, f"check_{check_host.get().strip()}.txt"
               )).pack(side="left", padx=2)

    check_host.bind("<Return>", do_check)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — Traceroute
    # ════════════════════════════════════════════════════════════════════════
    tab_trace = make_tab("🗺  Traceroute")
    tb3 = make_toolbar(tab_trace)

    toolbar_label(tb3, "Host:")
    trace_host = toolbar_entry(tb3, 26, "google.com")
    toolbar_label(tb3, "Max hops:")
    trace_hops = toolbar_entry(tb3, 4, "15")
    toolbar_sep(tb3)

    trace_out = make_output(make_content(tab_trace))
    trace_out.pack(fill="both", expand=True)

    def do_trace(*_):
        host = trace_host.get().strip()
        try:
            hops = int(trace_hops.get().strip() or "15")
        except ValueError:
            hops = 15
        if not host:
            return
        clear_out(trace_out)
        w(trace_out, f"Tracing route to {host}  (max {hops} hops)…\n\n", "accent")
        set_status(f"Traceroute to {host}…")

        def _run():
            r   = NetDiag.traceroute(host, hops)
            txt = format_traceroute(r)
            tag = "warn" if r.nat_warning else ("ok" if r.success else "err")
            root.after(0, lambda: w(trace_out, txt + "\n", tag))
            root.after(0, lambda: set_status(
                f"Traceroute {host} — {len(r.hops)} hops visible, "
                f"{r.filtered_hops} filtered"
                + ("  ⚠ PATH OBSCURED" if r.nat_warning else "")
            ))

        import threading
        threading.Thread(target=_run, daemon=True).start()

    ttk.Button(tb3, text="▶  Run", style="Accent.TButton",
               command=do_trace).pack(side="left", padx=2)
    ttk.Button(tb3, text="Clear",
               command=lambda: clear_out(trace_out)).pack(side="left", padx=2)
    ttk.Button(tb3, text="Export",
               command=lambda: export_output(
                   trace_out, f"traceroute_{trace_host.get().strip()}.txt"
               )).pack(side="left", padx=2)

    trace_host.bind("<Return>", do_trace)
    trace_hops.bind("<Return>", do_trace)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 — Monitor
    # ════════════════════════════════════════════════════════════════════════
    tab_mon = make_tab("📡  Monitor")
    tb4 = make_toolbar(tab_mon)

    toolbar_label(tb4, "Hosts:")
    mon_hosts_var = tk.StringVar(value=", ".join(DEFAULT_HOSTS))
    mon_hosts_entry = ttk.Entry(tb4, textvariable=mon_hosts_var, width=38)
    mon_hosts_entry.pack(side="left", padx=(0, 8))
    toolbar_label(tb4, "Interval (s):")
    mon_interval_entry = toolbar_entry(tb4, 4, str(MONITOR_INTERVAL))
    toolbar_sep(tb4)

    # Host status indicator row  (colored dots, updated live)
    indicator_frame = tk.Frame(tab_mon, bg=BG, pady=4)
    indicator_frame.pack(fill="x", padx=8)
    host_indicators: dict = {}   # host → tk.Label

    def _rebuild_indicators(hosts):
        for w_ in indicator_frame.winfo_children():
            w_.destroy()
        host_indicators.clear()
        tk.Label(indicator_frame, text="Status: ", bg=BG,
                 fg=SUBTLE, font=("Courier", 9)).pack(side="left")
        for h in hosts:
            lbl = tk.Label(indicator_frame,
                           text=f"⬤ {h}",
                           bg=BG, fg=SUBTLE,
                           font=("Courier", 9))
            lbl.pack(side="left", padx=6)
            host_indicators[h] = lbl

    def _set_indicator(host: str, ok: bool):
        lbl = host_indicators.get(host)
        if lbl:
            lbl.config(fg=GREEN if ok else RED)

    _rebuild_indicators(DEFAULT_HOSTS)

    mon_out = make_output(make_content(tab_mon))
    mon_out.pack(fill="both", expand=True)

    mon_running  = [False]
    mon_state_ref = [None]

    def mon_write(text: str, tag: str = ""):
        root.after(0, lambda: w(mon_out, text, tag))

    def do_monitor_tick(hosts, interval, state: MonitorState):
        if not mon_running[0]:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        for host in hosts:
            result = NetDiag.full_check(host)
            state.record(result)
            log_check(result)

            root.after(0, lambda h=host, ok=result.success: _set_indicator(h, ok))

            ip_alert  = state.check_ip_change(host, result.ip)
            asn_alert = state.check_asn_change(host, result.asn)
            if ip_alert:
                mon_write(f"\n⚠️  {host}: {ip_alert}\n", "warn")
            if asn_alert:
                mon_write(f"\n🚨 {host}: {asn_alert}\n", "err")

            stats = state.analyze(host)
            if not stats:
                mon_write(f"  [{ts}]  {host:<22} — collecting samples…\n", "subtle")
                continue

            avg = stats["avg"]
            spike_flag = ""
            if host not in state.baseline:
                state.baseline[host] = avg
            else:
                baseline = state.baseline[host]
                now = time.time()
                if avg > baseline * LATENCY_SPIKE_MULTIPLIER:
                    last = state.last_spike.get(host, 0)
                    if now - last > SPIKE_COOLDOWN:
                        mon_write(
                            f"\n⚠️  LATENCY SPIKE: {host}  "
                            f"avg={avg:.1f}ms  baseline={baseline:.1f}ms\n",
                            "warn"
                        )
                        state.last_spike[host] = now
                        spike_flag = " ⚠️"
                state.baseline[host] = (baseline * 0.9) + (avg * 0.1)

            if stats["loss"] > PACKET_LOSS_THRESHOLD:
                mon_write(f"\n🚨 PACKET LOSS: {host}  {stats['loss']:.0f}%\n", "err")

            dns_s  = f"{result.dns_ms:.1f}ms"  if result.dns_ms  else "N/A  "
            tcp_s  = f"{result.tcp_ms:.1f}ms"  if result.tcp_ms  else "FAIL "
            tls_s  = f"{result.tls_ms:.1f}ms"  if result.tls_ms  else "N/A  "
            http_s = str(result.http_status)    if result.http_status else "N/A"

            line = (
                f"  [{ts}]  {host:<22}  "
                f"dns={dns_s:<9}  tcp={tcp_s:<9}  "
                f"tls={tls_s:<9}  http={http_s}{spike_flag}\n"
            )
            tag = "ok" if result.success else "err"
            mon_write(line, tag)

        mon_write(f"{'─'*72}\n", "subtle")
        root.after(0, lambda: set_status(
            f"Monitor — last sweep {ts}  |  "
            f"{len(hosts)} host(s) active"
        ))

        if mon_running[0]:
            root.after(interval * 1000,
                       lambda: do_monitor_tick(hosts, interval, state))

    def start_monitor():
        if mon_running[0]:
            return
        hosts_raw = mon_hosts_var.get()
        hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]
        try:
            interval = int(mon_interval_entry.get().strip() or str(MONITOR_INTERVAL))
        except ValueError:
            interval = MONITOR_INTERVAL
        state = MonitorState()
        mon_state_ref[0] = state
        mon_running[0] = True
        clear_out(mon_out)
        _rebuild_indicators(hosts)
        w(mon_out, f"{TOOL_NAME} v{VERSION} — Monitor Mode\n", "head")
        w(mon_out, f"Hosts    : {', '.join(hosts)}\n", "accent")
        w(mon_out, f"Interval : {interval}s\n", "accent")
        w(mon_out, f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n",
          "accent")
        set_status(f"Monitor started — {len(hosts)} host(s)  interval={interval}s")

        import threading
        threading.Thread(
            target=lambda: do_monitor_tick(hosts, interval, state),
            daemon=True
        ).start()
        btn_mon_start.config(state="disabled")
        btn_mon_stop.config(state="normal")

    def stop_monitor():
        mon_running[0] = False
        mon_write("\n■  Monitor stopped.\n", "warn")
        for lbl in host_indicators.values():
            lbl.config(fg=SUBTLE)
        set_status("Monitor stopped.")
        btn_mon_start.config(state="normal")
        btn_mon_stop.config(state="disabled")

    btn_mon_start = ttk.Button(tb4, text="▶  Start",
                               style="Accent.TButton", command=start_monitor)
    btn_mon_start.pack(side="left", padx=2)
    btn_mon_stop  = ttk.Button(tb4, text="■  Stop",
                               command=stop_monitor, state="disabled")
    btn_mon_stop.pack(side="left", padx=2)
    ttk.Button(tb4, text="Clear",
               command=lambda: clear_out(mon_out)).pack(side="left", padx=2)
    ttk.Button(tb4, text="Export",
               command=lambda: export_output(
                   mon_out, f"monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
               )).pack(side="left", padx=2)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 5 — About
    # ════════════════════════════════════════════════════════════════════════
    tab_about = make_tab("ℹ  About")
    about_frame = ttk.Frame(tab_about)
    about_frame.pack(fill="both", expand=True, padx=30, pady=20)

    about_text = [
        (f"{TOOL_NAME}", "head"),
        (f"Version {VERSION}  |  Python {platform.python_version()}  |  {OS}\n\n", "subtle"),
        ("FEATURES\n", "subhead"),
        (
            "  DNS resolution timing          TCP connect latency\n"
            "  TLS handshake timing           HTTP/HTTPS status check\n"
            "  ASN / ISP / Geo lookup         Traceroute with bottleneck detection\n"
            "  Subnet-aware IP change alerts  ASN & route change detection\n"
            "  Adaptive latency baseline      Packet loss detection\n"
            "  CSV logging                    JSON output\n"
            "  NAT / WSL2 path warnings       Cross-platform (Linux, macOS, Windows)\n\n",
            "",
        ),
        ("CLI USAGE\n", "subhead"),
        (
            "  python sendgikoski_netcheck.py                    # this GUI\n"
            "  python sendgikoski_netcheck.py ping google.com    # ping\n"
            "  python sendgikoski_netcheck.py check google.com   # full check\n"
            "  python sendgikoski_netcheck.py traceroute HOST    # traceroute\n"
            "  python sendgikoski_netcheck.py all                # all hosts\n"
            "  python sendgikoski_netcheck.py monitor            # live monitor\n"
            "  python sendgikoski_netcheck.py --help             # full help\n\n",
            "accent",
        ),
        ("DEPENDENCIES\n", "subhead"),
        (
            "  stdlib only — no installation required for core features.\n"
            "  pip install requests   → enables ASN lookup, HTTP checks\n\n",
            "",
        ),
        ("PART OF THE SENDGIKOSKILABS SUITE\n", "subhead"),
        (
            "  netcheck   — single-host network diagnostics  (this tool)\n"
            "  ispinsight — ISP analysis, BGP, peering\n"
            "  logsleuth  — log analysis and anomaly detection\n"
            "  netwatch   — unified monitoring with Grafana integration\n\n",
            "",
        ),
        ("AUTHOR\n", "subhead"),
        (
            "  Alan Sendgikoski  —  SendgikoskiLabs\n"
            "  https://github.com/SendgikoskiLabs\n",
            "subtle",
        ),
    ]

    about_out = make_output(about_frame)
    about_out.pack(fill="both", expand=True)
    for text, tag in about_text:
        w(about_out, text + ("\n" if not text.endswith("\n") else ""), tag)

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
