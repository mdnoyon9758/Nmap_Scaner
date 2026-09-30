"""
Web surface recon: robots.txt, sitemap.xml, security.txt, and a small,
polite probe of well-known sensitive paths.

This checks for the *existence and exposure* of common files/paths that
frequently leak information in web apps (e.g. an exposed .git/config or
.env). It only issues GET/HEAD requests to a bounded, well-known list and
honors the configured rate limit — it is not a brute-force fuzzer.
"""

from __future__ import annotations

import concurrent.futures as cf

from reconx.core.report import Finding
from reconx.core.net import http_request
from . import BaseModule, register

# Well-known standards files.
WELL_KNOWN = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/security.txt", "/humans.txt",
]

# Commonly-misconfigured sensitive paths. Presence often indicates leakage.
SENSITIVE_PATHS = {
    "/.git/config": ("high", "Exposed Git repository config"),
    "/.git/HEAD": ("high", "Exposed Git repository"),
    "/.env": ("high", "Exposed environment file (may contain secrets)"),
    "/.svn/entries": ("medium", "Exposed SVN metadata"),
    "/.DS_Store": ("low", "Exposed macOS .DS_Store (directory listing leak)"),
    "/config.php.bak": ("medium", "Exposed backup config file"),
    "/wp-config.php.bak": ("high", "Exposed WordPress config backup"),
    "/phpinfo.php": ("medium", "Exposed phpinfo()"),
    "/server-status": ("medium", "Exposed Apache server-status"),
    "/.htaccess": ("low", "Accessible .htaccess"),
    "/backup.zip": ("medium", "Exposed backup archive"),
    "/.aws/credentials": ("high", "Exposed AWS credentials file"),
}


def _base(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return "https://" + target.rstrip("/")


@register
class WebReconModule(BaseModule):
    name = "web"
    description = "Check robots/sitemap/security.txt and exposed sensitive paths"

    def _check(self, url: str, method: str = "GET"):
        self.limiter.acquire()
        try:
            status, headers, body = http_request(
                url, method=method, timeout=self.timeout,
                verify_tls=self.opts.get("verify_tls", True),
                max_bytes=64_000)
            return status, headers, body
        except Exception:
            return None

    def run(self, target: str):
        result = self._result(target)
        base = _base(target)

        # Well-known files (informational).
        for path in WELL_KNOWN:
            res = self._check(base + path)
            if res and res[0] == 200 and res[2]:
                snippet = res[2].decode("utf-8", "replace")[:500]
                result.findings.append(Finding(
                    module=self.name, target=target, severity="info",
                    title=f"Found {path}",
                    detail=snippet,
                    data={"path": path, "status": 200}))

        # Sensitive paths (concurrent, bounded).
        def probe(path):
            res = self._check(base + path, method="GET")
            if res and res[0] == 200:
                return path, res[0]
            return None

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 10)) as ex:
            for fut in cf.as_completed(
                    [ex.submit(probe, p) for p in SENSITIVE_PATHS]):
                res = fut.result()
                if res:
                    path, status = res
                    sev, desc = SENSITIVE_PATHS[path]
                    result.findings.append(Finding(
                        module=self.name, target=target, severity=sev,
                        title=desc,
                        detail=f"{base + path} returned HTTP {status}",
                        data={"path": path, "status": status}))

        if not result.findings:
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title="No well-known or exposed sensitive paths found"))
        return self._finish(result)
