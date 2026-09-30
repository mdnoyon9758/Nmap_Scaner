"""
Orchestrator: run a selection of modules across a set of targets and
collect everything into a single Report.
"""

from __future__ import annotations

from reconx.core.report import Report, ModuleResult
from reconx.core.net import DEFAULT_TIMEOUT
from reconx.modules import load_all

# Sensible module groupings for common workflows.
PROFILES = {
    "quick": ["portscan", "headers"],
    "recon": ["dns", "subdomains", "whois", "headers", "tech", "tls"],
    "web": ["headers", "tech", "tls", "web"],
    "full": ["dns", "subdomains", "whois", "portscan",
             "headers", "tech", "tls", "web"],
}


class Toolkit:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT, rate: float = 0.0,
                 threads: int = 50, **opts):
        self.registry = load_all()
        self.timeout = timeout
        self.rate = rate
        self.threads = threads
        self.opts = opts

    def available(self) -> dict[str, str]:
        return {name: cls.description for name, cls in self.registry.items()}

    def resolve_modules(self, selection) -> list[str]:
        if not selection:
            return PROFILES["recon"]
        if isinstance(selection, str):
            selection = [selection]
        resolved: list[str] = []
        for item in selection:
            if item in PROFILES:
                resolved.extend(PROFILES[item])
            elif item == "all":
                resolved.extend(self.registry.keys())
            elif item in self.registry:
                resolved.append(item)
            else:
                raise ValueError(f"Unknown module/profile: {item}")
        # de-dupe, preserve order
        seen, ordered = set(), []
        for m in resolved:
            if m not in seen:
                seen.add(m)
                ordered.append(m)
        return ordered

    def run(self, targets, modules=None, report_title="ReconX Assessment",
            progress=None) -> Report:
        if isinstance(targets, str):
            targets = [targets]
        module_names = self.resolve_modules(modules)
        report = Report(report_title)

        for target in targets:
            for name in module_names:
                cls = self.registry[name]
                mod = cls(timeout=self.timeout, rate=self.rate,
                          threads=self.threads, **self.opts)
                if progress:
                    progress(target, name)
                try:
                    result = mod.run(target)
                except Exception as exc:  # never let one module kill the run
                    result = ModuleResult(module=name, target=target,
                                          error=f"module crashed: {exc}")
                report.add(result)
        return report
