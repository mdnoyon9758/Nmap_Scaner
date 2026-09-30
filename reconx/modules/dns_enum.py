"""DNS record enumeration using the built-in stdlib resolver."""

from __future__ import annotations

from reconx.core.report import Finding
from reconx.core.net import dns_query, is_ip
from . import BaseModule, register

RECORD_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA"]


@register
class DnsEnumModule(BaseModule):
    name = "dns"
    description = "Enumerate DNS records (A/AAAA/NS/MX/TXT/CNAME/SOA)"

    def run(self, target: str):
        result = self._result(target)
        if is_ip(target):
            result.error = "DNS enumeration expects a hostname, not an IP."
            return self._finish(result)

        found_any = False
        for rtype in RECORD_TYPES:
            self.limiter.acquire()
            try:
                answers = dns_query(target, rtype, timeout=self.timeout)
            except ValueError:
                continue
            if answers:
                found_any = True
                sev = "info"
                # SPF/DMARC absence is worth flagging for a domain.
                result.findings.append(Finding(
                    module=self.name, target=target, severity=sev,
                    title=f"{rtype} records ({len(answers)})",
                    detail="\n".join(answers),
                    data={"type": rtype, "answers": answers},
                ))

        # Basic email-security posture checks from TXT records.
        txt = dns_query(target, "TXT", timeout=self.timeout)
        joined = " ".join(txt).lower()
        if txt and "v=spf1" not in joined:
            result.findings.append(Finding(
                module=self.name, target=target, severity="low",
                title="No SPF record found",
                detail="Domain has TXT records but no SPF (v=spf1) policy, "
                       "which can enable email spoofing.",
            ))
        dmarc = dns_query(f"_dmarc.{target}", "TXT", timeout=self.timeout)
        if not any("v=dmarc1" in d.lower() for d in dmarc):
            result.findings.append(Finding(
                module=self.name, target=target, severity="low",
                title="No DMARC record found",
                detail="No _dmarc TXT policy found; weakens phishing "
                       "protection for this domain.",
            ))

        if not found_any:
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title="No DNS records resolved",
            ))
        return self._finish(result)
