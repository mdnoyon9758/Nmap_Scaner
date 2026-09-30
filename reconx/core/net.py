"""
Shared networking helpers for ReconX — all standard library.

Includes:
  * a token-bucket RateLimiter (be a good citizen; avoid hammering targets)
  * target parsing / validation (host, IP, CIDR expansion)
  * a compact pure-stdlib DNS resolver (A, AAAA, MX, NS, TXT, CNAME, SOA)
  * a small HTTP helper built on urllib with sane defaults
"""

from __future__ import annotations

import os
import ssl
import time
import socket
import struct
import random
import ipaddress
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = float(os.environ.get("RECONX_TIMEOUT", "5"))
USER_AGENT = "ReconX/2.0 (+authorized-security-assessment)"


class RateLimiter:
    """Simple thread-safe token bucket. rate = operations per second."""

    def __init__(self, rate: float = 0.0):
        # rate <= 0 means "no limit"
        self.rate = float(rate)
        self._lock = threading.Lock()
        self._allowance = float(rate) if rate > 0 else 0.0
        self._last = time.monotonic()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            self._allowance += (now - self._last) * self.rate
            self._last = now
            if self._allowance > self.rate:
                self._allowance = self.rate
            if self._allowance < 1.0:
                sleep_for = (1.0 - self._allowance) / self.rate
                time.sleep(sleep_for)
                self._allowance = 0.0
            else:
                self._allowance -= 1.0


# --------------------------------------------------------------------------
# Target handling
# --------------------------------------------------------------------------

@dataclass
class Target:
    raw: str
    host: str
    ip: str | None = None
    is_cidr: bool = False


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def expand_targets(raw: str) -> list[str]:
    """Expand a CIDR range into individual host IPs; otherwise return [raw]."""
    raw = raw.strip()
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            # Guard against absurd expansions.
            if net.num_addresses > 65536:
                raise ValueError(
                    f"Refusing to expand {raw}: {net.num_addresses} hosts "
                    "(limit 65536). Narrow the range."
                )
            hosts = list(net.hosts()) or [net.network_address]
            return [str(h) for h in hosts]
        except ValueError as exc:
            if "Refusing" in str(exc):
                raise
    return [raw]


def resolve_host(host: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
    if is_ip(host):
        return host
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(host)
    except (socket.gaierror, socket.timeout, OSError):
        return None


# --------------------------------------------------------------------------
# Minimal DNS resolver (RFC 1035) — no third-party deps
# --------------------------------------------------------------------------

_QTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6,
    "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
}
_QTYPE_NAMES = {v: k for k, v in _QTYPES.items()}
_PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("idna")
    return out + b"\x00"


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    end_offset = offset
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if not jumped:
        end_offset = offset
    return ".".join(labels), end_offset


def dns_query(name: str, qtype: str = "A",
              resolver: str | None = None,
              timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Query a single record type. Returns a list of string answers."""
    qt = _QTYPES.get(qtype.upper())
    if qt is None:
        raise ValueError(f"Unsupported record type: {qtype}")

    resolvers = [resolver] if resolver else list(_PUBLIC_RESOLVERS)
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(name) + struct.pack(">HH", qt, 1)
    packet = header + question

    for res in resolvers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (res, 53))
            data, _ = sock.recvfrom(4096)
            sock.close()
            # If the response is truncated (TC bit), retry over TCP.
            flags = struct.unpack(">H", data[2:4])[0]
            if flags & 0x0200:
                tcp_data = _dns_query_tcp(packet, res, timeout)
                if tcp_data:
                    data = tcp_data
            return _parse_dns_answers(data)
        except (socket.timeout, OSError):
            continue
    return []


def _dns_query_tcp(packet: bytes, resolver: str, timeout: float) -> bytes | None:
    """DNS over TCP (RFC 1035 §4.2.2): 2-byte length prefix."""
    try:
        with socket.create_connection((resolver, 53), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack(">H", len(packet)) + packet)
            length_bytes = _recv_exact(sock, 2)
            if not length_bytes:
                return None
            resp_len = struct.unpack(">H", length_bytes)[0]
            return _recv_exact(sock, resp_len)
    except OSError:
        return None


def _recv_exact(sock, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _parse_dns_answers(data: bytes) -> list[str]:
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return []
    # Skip header + question
    offset = 12
    _, offset = _read_name(data, offset)
    offset += 4  # qtype + qclass

    answers = []
    for _ in range(ancount):
        _, offset = _read_name(data, offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        name = _QTYPE_NAMES.get(rtype, str(rtype))
        if rtype == 1 and rdlength == 4:                       # A
            answers.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlength == 16:                   # AAAA
            answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype in (2, 5, 12):                              # NS/CNAME/PTR
            target, _ = _read_name(data, offset)
            answers.append(target)
        elif rtype == 15:                                      # MX
            pref = struct.unpack(">H", rdata[:2])[0]
            exch, _ = _read_name(data, offset + 2)
            answers.append(f"{pref} {exch}")
        elif rtype == 16:                                      # TXT
            txt, pos = [], 0
            while pos < len(rdata):
                ln = rdata[pos]
                txt.append(rdata[pos + 1:pos + 1 + ln].decode("utf-8", "replace"))
                pos += 1 + ln
            answers.append("".join(txt))
        elif rtype == 6:                                       # SOA
            mname, o2 = _read_name(data, offset)
            rname, _ = _read_name(data, o2)
            answers.append(f"{mname} {rname}")
        offset += rdlength
    return answers


# --------------------------------------------------------------------------
# HTTP helper
# --------------------------------------------------------------------------

def http_request(url: str, method: str = "GET",
                 timeout: float = DEFAULT_TIMEOUT,
                 headers: dict | None = None,
                 verify_tls: bool = True,
                 max_bytes: int = 2_000_000):
    """
    Perform a single HTTP(S) request. Returns (status, headers_dict, body_bytes)
    or raises urllib.error.URLError. Does not follow into private ranges blindly;
    the caller is responsible for scope.
    """
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    ctx = None
    if url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read(max_bytes)
        return resp.status, dict(resp.headers.items()), body
