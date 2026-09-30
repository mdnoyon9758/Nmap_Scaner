"""
Subdomain enumeration.

Two passive/standard techniques, both used routinely in authorized
bug-bounty recon:
  1. Certificate Transparency logs via crt.sh (passive, no target contact).
  2. Optional wordlist-based DNS resolution (active, resolves candidates).
"""

from __future__ import annotations

import json
import concurrent.futures as cf

from reconx.core.report import Finding
from reconx.core.net import dns_query, http_request, is_ip
from . import BaseModule, register

# A compact built-in wordlist; users can supply their own via opts["wordlist"].
DEFAULT_WORDS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "api", "dev", "staging", "stage", "test", "testing", "uat",
    "admin", "portal", "vpn", "remote", "gateway", "gw", "app", "apps",
    "blog", "shop", "store", "cdn", "static", "assets", "img", "images",
    "media", "docs", "support", "help", "status", "monitor", "grafana",
    "kibana", "jenkins", "git", "gitlab", "jira", "confluence", "db",
    "database", "mysql", "postgres", "redis", "cache", "internal", "intranet",
    "corp", "cloud", "aws", "azure", "gcp", "k8s", "kube", "auth", "sso",
    "login", "secure", "beta", "demo", "sandbox", "preprod", "prod",
    "mobile", "m", "wap", "ww1", "email", "mx", "mx1", "mx2", "smtp1",
]


@register
class SubdomainModule(BaseModule):
    name = "subdomains"
    description = "Enumerate subdomains (crt.sh + optional DNS wordlist)"

    def _ct_logs(self, domain: str) -> set[str]:
        found: set[str] = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            self.limiter.acquire()
            status, _, body = http_request(url, timeout=max(self.timeout, 15))
            if status == 200 and body:
                for entry in json.loads(body.decode("utf-8", "replace")):
                    for name in str(entry.get("name_value", "")).splitlines():
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain):
                            found.add(name)
        except Exception:
            pass  # CT is best-effort; wordlist still runs.
        return found

    def _resolve_word(self, word: str, domain: str):
        host = f"{word}.{domain}"
        self.limiter.acquire()
        answers = dns_query(host, "A", timeout=self.timeout)
        if answers:
            return host, answers
        return None

    def run(self, target: str):
        result = self._result(target)
        if is_ip(target):
            result.error = "Subdomain enumeration expects a domain, not an IP."
            return self._finish(result)

        discovered: dict[str, list] = {}

        # 1) Passive: certificate transparency
        for sub in self._ct_logs(target):
            discovered.setdefault(sub, [])

        # 2) Active: wordlist resolution (optional)
        if self.opts.get("wordlist_enabled", True):
            words = self.opts.get("words") or DEFAULT_WORDS
            with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = [ex.submit(self._resolve_word, w, target)
                           for w in words]
                for fut in cf.as_completed(futures):
                    res = fut.result()
                    if res:
                        host, ips = res
                        discovered[host] = ips

        if not discovered:
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title="No subdomains discovered",
            ))
        else:
            live = {k: v for k, v in discovered.items() if v}
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title=f"{len(discovered)} subdomains discovered "
                      f"({len(live)} resolving)",
                detail="\n".join(
                    f"{h}" + (f" -> {', '.join(ips)}" if ips else "")
                    for h, ips in sorted(discovered.items())
                ),
                data={"subdomains": discovered},
            ))
        return self._finish(result)
