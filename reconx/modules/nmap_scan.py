"""
Optional nmap-backed deep scan.

ReconX is fully functional without nmap (see portscan module), but when
nmap *is* installed this module unlocks its deeper capabilities — service/
version detection, OS fingerprinting, and NSE scripts. It reuses the
existing project wrapper in ``scanner.nmap_wrapper`` so the desktop GUI and
the toolkit share one code path.
"""

from __future__ import annotations

from reconx.core.report import Finding
from . import BaseModule, register

# Safe, read-only scan types exposed through the toolkit. We deliberately do
# not expose intrusive NSE categories here.
SCAN_TYPES = {
    "quick": "Quick Scan",
    "intense": "Intense Scan",
    "service": "Service Detection",
    "ping": "Ping Scan",
}


@register
class NmapScanModule(BaseModule):
    name = "nmap"
    description = "Deep scan via nmap when installed (service/OS/NSE)"

    def run(self, target: str):
        result = self._result(target)
        try:
            from scanner.nmap_wrapper import NmapScanner
        except Exception as exc:
            result.error = f"nmap wrapper unavailable: {exc}"
            return self._finish(result)

        scanner = NmapScanner()
        if not scanner.nmap_available:
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title="nmap not installed — using built-in portscan instead",
                detail="Install nmap for service/version/OS detection, or run "
                       "the 'portscan' module which needs no external binary."))
            return self._finish(result)

        scan_type = SCAN_TYPES.get(
            self.opts.get("nmap_scan_type", "service"), "Service Detection")
        ports = self.opts.get("ports")
        raw = scanner.scan(target, scan_type=scan_type, port_range=ports)

        if raw.get("error"):
            result.error = raw["error"]
            return self._finish(result)

        info = raw.get("scanner_info")
        hosts = raw.get("hosts", [])
        if not hosts:
            result.findings.append(Finding(
                module=self.name, target=target, severity="info",
                title="Host down or no results"))
            return self._finish(result)

        for host in hosts:
            if not (info and host in info.all_hosts()):
                continue
            for proto in info[host].all_protocols():
                for port in sorted(info[host][proto].keys()):
                    pinfo = info[host][proto][port]
                    name = pinfo.get("name", "unknown")
                    product = pinfo.get("product", "")
                    version = pinfo.get("version", "")
                    svc = " ".join(x for x in (name, product, version) if x)
                    result.findings.append(Finding(
                        module=self.name, target=host, severity="info",
                        title=f"{port}/{proto} {pinfo.get('state','')} ({svc})",
                        data={"port": port, "proto": proto, **dict(pinfo)}))
            for osm in info[host].get("osmatch", []) or []:
                result.findings.append(Finding(
                    module=self.name, target=host, severity="info",
                    title=f"OS guess: {osm.get('name','?')} "
                          f"({osm.get('accuracy','?')}%)"))
        return self._finish(result)
