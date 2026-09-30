"""
Lightweight web technology fingerprinting.

Infers server-side/frontend technologies from response headers, cookies,
and simple body markers. Passive signal only — no exploitation.
"""

from __future__ import annotations

import re

from reconx.core.report import Finding
from reconx.core.net import http_request
from . import BaseModule, register

HEADER_SIGNS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal",
    "x-shopify-stage": "Shopify",
    "x-aspnet-version": "ASP.NET",
}

BODY_SIGNS = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"/sites/default/files|Drupal\.settings", "Drupal"),
    (r"Joomla!", "Joomla"),
    (r"__NEXT_DATA__|/_next/", "Next.js"),
    (r"ng-version=", "Angular"),
    (r"data-reactroot|react\.production", "React"),
    (r"window\.__NUXT__", "Nuxt.js"),
    (r"csrf-param|rails", "Ruby on Rails"),
    (r"laravel_session", "Laravel"),
    (r"cf-ray|cloudflare", "Cloudflare"),
]

COOKIE_SIGNS = [
    ("PHPSESSID", "PHP"),
    ("JSESSIONID", "Java/JSP"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("csrftoken", "Django"),
    ("_shopify", "Shopify"),
]


def _normalize_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return "https://" + target


@register
class TechFingerprintModule(BaseModule):
    name = "tech"
    description = "Fingerprint web technologies (passive)"

    def run(self, target: str):
        result = self._result(target)
        url = _normalize_url(target)
        self.limiter.acquire()
        try:
            status, headers, body = http_request(
                url, timeout=self.timeout,
                verify_tls=self.opts.get("verify_tls", True))
        except Exception as exc:
            result.error = f"Request failed: {exc}"
            return self._finish(result)

        tech: set[str] = set()
        lower = {k.lower(): v for k, v in headers.items()}
        for hdr, label in HEADER_SIGNS.items():
            if hdr in lower and lower[hdr].strip():
                tech.add(f"{label}: {lower[hdr]}")

        cookie = lower.get("set-cookie", "")
        for marker, label in COOKIE_SIGNS:
            if marker in cookie:
                tech.add(label)

        text = body.decode("utf-8", "replace")[:200000]
        for pattern, label in BODY_SIGNS:
            if re.search(pattern, text, re.IGNORECASE):
                tech.add(label)

        # <meta name="generator" ...>
        for m in re.finditer(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                text, re.IGNORECASE):
            tech.add(f"Generator: {m.group(1)}")

        if tech:
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title=f"{len(tech)} technologies fingerprinted",
                detail="\n".join(sorted(tech)),
                data={"technologies": sorted(tech), "status": status}))
        else:
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title="No technologies fingerprinted from surface signals"))
        return self._finish(result)
