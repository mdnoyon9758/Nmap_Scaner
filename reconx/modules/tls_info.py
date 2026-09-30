"""
TLS/SSL certificate inspection.

Connects to a host:port over TLS and reports the negotiated protocol,
certificate subject/issuer, validity window, and SAN list. Flags expired
or soon-to-expire certificates and deprecated protocol versions.
"""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone

from reconx.core.report import Finding
from . import BaseModule, register


def _parse_dt(value: str):
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


@register
class TlsInfoModule(BaseModule):
    name = "tls"
    description = "Inspect TLS certificate and negotiated protocol"

    def run(self, target: str):
        result = self._result(target)
        host = target
        port = int(self.opts.get("port", 443))
        if ":" in target and not target.count(":") > 1:
            host, p = target.split(":", 1)
            port = int(p)

        ctx = ssl.create_default_context()
        # We still connect even if the cert is invalid so we can *report* it.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.limiter.acquire()
        try:
            with socket.create_connection((host, port), self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    proto = ssock.version()
                    cert = ssock.getpeercert(binary_form=False)
                    # getpeercert() is empty when verify_mode=CERT_NONE, so
                    # re-fetch parsed cert via a verifying context best-effort.
        except (OSError, ssl.SSLError) as exc:
            result.error = f"TLS connection failed: {exc}"
            return self._finish(result)

        # Second pass: get a parsed cert using a default verifying context,
        # but tolerate verification failure (self-signed / expired).
        cert = {}
        verify_error = None
        vctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), self.timeout) as sock:
                with vctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
        except ssl.SSLCertVerificationError as exc:
            verify_error = str(exc)
        except (OSError, ssl.SSLError):
            pass

        detail = [f"protocol: {proto}"]
        if verify_error:
            detail.append(f"verification: FAILED ({verify_error})")
            result.findings.append(Finding(
                module=self.name, target=target, severity="medium",
                title="TLS certificate failed verification",
                detail=verify_error))

        if cert:
            subj = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            detail.append(f"subject CN: {subj.get('commonName', '?')}")
            detail.append(f"issuer: {issuer.get('organizationName', '?')} / "
                          f"{issuer.get('commonName', '?')}")
            not_after = cert.get("notAfter", "")
            detail.append(f"not before: {cert.get('notBefore', '?')}")
            detail.append(f"not after: {not_after}")
            sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
            if sans:
                detail.append("SANs: " + ", ".join(sans[:30]))

            exp = _parse_dt(not_after)
            if exp:
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    result.findings.append(Finding(
                        module=self.name, target=target, severity="high",
                        title=f"Certificate EXPIRED {abs(days)} days ago"))
                elif days < 15:
                    result.findings.append(Finding(
                        module=self.name, target=target, severity="medium",
                        title=f"Certificate expires in {days} days"))

        if proto in ("SSLv3", "TLSv1", "TLSv1.1"):
            result.findings.append(Finding(
                module=self.name, target=target, severity="medium",
                title=f"Deprecated TLS protocol negotiated: {proto}"))

        result.findings.insert(0, Finding(
            module=self.name, target=target, severity="info",
            title=f"TLS on {host}:{port}",
            detail="\n".join(detail),
            data={"protocol": proto, "certificate": cert}))
        return self._finish(result)
