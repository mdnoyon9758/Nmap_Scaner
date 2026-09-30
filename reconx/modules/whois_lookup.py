"""
WHOIS lookup over the standard whois protocol (TCP/43), pure stdlib.

Queries IANA to find the authoritative whois server for the TLD, then
queries that server. Falls back to a few well-known servers.
"""

from __future__ import annotations

import socket

from reconx.core.report import Finding
from reconx.core.net import is_ip
from . import BaseModule, register

FALLBACK_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
}


def _query(server: str, query: str, timeout: float) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, 43))
        s.sendall((query + "\r\n").encode("utf-8", "replace"))
        chunks = []
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")


@register
class WhoisModule(BaseModule):
    name = "whois"
    description = "WHOIS registration lookup (domain or IP)"

    def run(self, target: str):
        result = self._result(target)
        try:
            if is_ip(target):
                text = _query("whois.arin.net", target, self.timeout)
            else:
                tld = target.rsplit(".", 1)[-1].lower()
                # Ask IANA which server is authoritative for this TLD.
                server = None
                try:
                    iana = _query("whois.iana.org", target, self.timeout)
                    for line in iana.splitlines():
                        if line.lower().startswith("whois:"):
                            server = line.split(":", 1)[1].strip()
                            break
                except OSError:
                    pass
                server = server or FALLBACK_SERVERS.get(tld, "whois.iana.org")
                text = _query(server, target, self.timeout)
        except OSError as exc:
            result.error = f"WHOIS query failed: {exc}"
            return self._finish(result)

        # Surface the most useful lines rather than the whole dump.
        keys = ("registrar", "creation date", "created", "expiry",
                "expiration", "updated", "name server", "org",
                "organisation", "netname", "cidr", "country", "status")
        highlights = [
            ln.strip() for ln in text.splitlines()
            if ln.strip() and ln.split(":", 1)[0].strip().lower() in keys
        ]
        result.findings.append(Finding(
            module=self.name, target=target, severity="info",
            title="WHOIS record",
            detail="\n".join(highlights) if highlights else text[:1500],
            data={"raw": text[:8000]},
        ))
        return self._finish(result)
