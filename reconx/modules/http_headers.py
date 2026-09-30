"""
HTTP security-header analysis.

Fetches a URL and evaluates the response headers against common hardening
best practices (HSTS, CSP, X-Frame-Options, etc.) and flags information
leakage (verbose Server/X-Powered-By banners). Standard web-assessment.
"""

from __future__ import annotations

from reconx.core.report import Finding
from reconx.core.net import http_request
from . import BaseModule, register

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS not set", "medium",
        "Missing Strict-Transport-Security; connection can be downgraded."),
    "content-security-policy": ("CSP not set", "medium",
        "Missing Content-Security-Policy; weaker XSS/injection defense."),
    "x-frame-options": ("X-Frame-Options not set", "low",
        "Missing anti-clickjacking header (or CSP frame-ancestors)."),
    "x-content-type-options": ("X-Content-Type-Options not set", "low",
        "Missing nosniff; browsers may MIME-sniff responses."),
    "referrer-policy": ("Referrer-Policy not set", "info",
        "No referrer policy; referrers may leak to third parties."),
    "permissions-policy": ("Permissions-Policy not set", "info",
        "No Permissions-Policy to restrict browser features."),
}

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                 "x-aspnetmvc-version", "x-generator"]


def _normalize_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return "https://" + target


@register
class HttpHeadersModule(BaseModule):
    name = "headers"
    description = "Analyze HTTP response security headers"

    def run(self, target: str):
        result = self._result(target)
        url = _normalize_url(target)
        self.limiter.acquire()
        try:
            status, headers, _ = http_request(
                url, timeout=self.timeout,
                verify_tls=self.opts.get("verify_tls", True))
        except Exception as exc:
            # Retry over http:// if https failed and no scheme was given.
            if not target.startswith(("http://", "https://")):
                try:
                    status, headers, _ = http_request(
                        "http://" + target, timeout=self.timeout)
                    url = "http://" + target
                except Exception as exc2:
                    result.error = f"Request failed: {exc2}"
                    return self._finish(result)
            else:
                result.error = f"Request failed: {exc}"
                return self._finish(result)

        lower = {k.lower(): v for k, v in headers.items()}
        result.findings.append(Finding(
            module=self.name, target=target, severity="info",
            title=f"HTTP {status} from {url}",
            detail="\n".join(f"{k}: {v}" for k, v in headers.items()),
            data={"status": status, "headers": headers, "url": url},
        ))

        for hdr, (title, sev, detail) in SECURITY_HEADERS.items():
            if hdr not in lower:
                result.findings.append(Finding(
                    module=self.name, target=target, severity=sev,
                    title=title, detail=detail))

        for hdr in LEAKY_HEADERS:
            if hdr in lower and lower[hdr].strip():
                result.findings.append(Finding(
                    module=self.name, target=target, severity="low",
                    title=f"Information disclosure via '{hdr}' header",
                    detail=f"{hdr}: {lower[hdr]}"))
        return self._finish(result)
