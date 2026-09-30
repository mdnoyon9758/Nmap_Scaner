"""
ReconX modules.

Each module subclasses :class:`BaseModule` and implements ``run(target)``
returning a :class:`reconx.core.report.ModuleResult`. Modules register
themselves in ``REGISTRY`` so the CLI / orchestrator can discover them.
"""

from __future__ import annotations

from datetime import datetime, timezone

from reconx.core.report import ModuleResult, Finding
from reconx.core.net import RateLimiter, DEFAULT_TIMEOUT

REGISTRY: dict[str, type] = {}


def register(cls):
    REGISTRY[cls.name] = cls
    return cls


class BaseModule:
    name = "base"
    description = "base module"

    def __init__(self, timeout: float = DEFAULT_TIMEOUT,
                 rate: float = 0.0, threads: int = 50, **opts):
        self.timeout = timeout
        self.limiter = RateLimiter(rate)
        self.threads = threads
        self.opts = opts

    def _result(self, target: str) -> ModuleResult:
        return ModuleResult(
            module=self.name,
            target=target,
            started=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _finish(result: ModuleResult) -> ModuleResult:
        result.finished = datetime.now(timezone.utc).isoformat()
        return result

    def run(self, target: str) -> ModuleResult:  # pragma: no cover
        raise NotImplementedError


def load_all():
    """Import every module so the registry is populated."""
    from . import (  # noqa: F401
        portscan, dns_enum, subdomains, whois_lookup,
        http_headers, tls_info, tech_fingerprint, web_recon,
        nmap_scan,
    )
    return REGISTRY
