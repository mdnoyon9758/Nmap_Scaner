"""
Pure-Python TCP connect port scanner with light banner grabbing.

Works with no external binaries (no nmap required), so it runs on any
platform Python runs on. For deeper scans (OS detection, UDP, NSE scripts)
ReconX will delegate to nmap when it is installed, but this module keeps
the toolkit fully functional on its own.
"""

from __future__ import annotations

import socket
import concurrent.futures as cf

from reconx.core.report import Finding
from reconx.core.net import resolve_host
from . import BaseModule, register

# Common service ports — a sensible default set for quick triage.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1025, 1433, 1521, 1723, 2049, 2082, 2083,
    2181, 2375, 2376, 3000, 3306, 3389, 4444, 5000, 5432, 5601, 5672,
    5900, 5985, 5986, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9042, 9092, 9200, 9300, 10000, 11211, 15672, 27017, 27018,
]

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}


def parse_ports(spec: str | None) -> list[int]:
    if not spec:
        return list(TOP_PORTS)
    if spec.lower() in ("top", "common"):
        return list(TOP_PORTS)
    if spec.lower() == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


@register
class PortScanModule(BaseModule):
    name = "portscan"
    description = "TCP connect port scan + banner grab (no nmap needed)"

    def _probe(self, ip: str, port: int):
        self.limiter.acquire()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((ip, port)) != 0:
                    return None
                banner = ""
                try:
                    s.settimeout(min(self.timeout, 2.0))
                    if port in (80, 8080, 8000, 8888):
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(256)
                    banner = data.decode("latin-1", "replace").strip()
                except (socket.timeout, OSError):
                    pass
                return port, banner
        except OSError:
            return None

    def run(self, target: str):
        result = self._result(target)
        ip = resolve_host(target, self.timeout)
        if not ip:
            result.error = f"Could not resolve '{target}'"
            return self._finish(result)

        ports = parse_ports(self.opts.get("ports"))
        open_ports = []
        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._probe, ip, p): p for p in ports}
            for fut in cf.as_completed(futures):
                res = fut.result()
                if res:
                    open_ports.append(res)

        open_ports.sort()
        if not open_ports:
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title=f"No open TCP ports found (scanned {len(ports)})",
            ))
        for port, banner in open_ports:
            svc = COMMON_SERVICES.get(port, "unknown")
            sev = "info"
            # Flag a few classically risky exposed services.
            if port in (23, 3389, 6379, 9200, 11211, 27017, 5432, 3306):
                sev = "medium"
            detail = f"service={svc}"
            if banner:
                detail += f"\nbanner: {banner[:200]}"
            result.findings.append(Finding(
                module=self.name, target=target, severity=sev,
                title=f"{port}/tcp open ({svc})", detail=detail,
                data={"port": port, "service": svc, "banner": banner, "ip": ip},
            ))
        return self._finish(result)
