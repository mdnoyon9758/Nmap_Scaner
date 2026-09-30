"""
Authorization / scope gate.

ReconX is an offensive-security *assessment* tool. Running active scans
against systems you do not own or are not explicitly authorized to test is
illegal in most jurisdictions. This module makes authorization an explicit,
auditable step rather than an afterthought.

Authorization can be granted in three ways (checked in order):

  1. ``--i-am-authorized`` CLI flag (or ``authorized=True`` to the API).
  2. The ``RECONX_AUTHORIZED=1`` environment variable (useful in CI / labs).
  3. An interactive typed confirmation (only when attached to a TTY).

Every authorized run is written to an audit log so there is a record of
what was tested, when, and against which scope.
"""

from __future__ import annotations

import os
import sys
import json
import getpass
import platform
from datetime import datetime, timezone
from pathlib import Path

AUDIT_DIR = Path(os.environ.get("RECONX_HOME", Path.home() / ".reconx"))
AUDIT_LOG = AUDIT_DIR / "audit.log"

BANNER = """\
┌────────────────────────────────────────────────────────────────────┐
│  ReconX — Authorized Security Assessment Toolkit                     │
│                                                                      │
│  Only scan systems you OWN or have WRITTEN PERMISSION to test        │
│  (a signed engagement, an in-scope bug-bounty program, or your own   │
│  lab). Unauthorized scanning may be a criminal offense.              │
└────────────────────────────────────────────────────────────────────┘"""


class AuthorizationError(RuntimeError):
    """Raised when a scan is attempted without confirmed authorization."""


def _write_audit(targets, extra: dict | None = None) -> None:
    try:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": getpass.getuser(),
            "host": platform.node(),
            "targets": list(targets) if not isinstance(targets, str) else [targets],
        }
        if extra:
            record.update(extra)
        with AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        # Auditing must never crash a scan; fail silent.
        pass


def confirm_authorization(
    targets,
    authorized: bool = False,
    assume_yes: bool = False,
    quiet: bool = False,
) -> bool:
    """
    Confirm the operator is authorized to test ``targets``.

    Returns True on success, raises :class:`AuthorizationError` otherwise.
    """
    if not quiet:
        print(BANNER, file=sys.stderr)

    granted = bool(authorized) or os.environ.get("RECONX_AUTHORIZED") == "1"

    if not granted and assume_yes:
        granted = True

    if not granted:
        if not sys.stdin.isatty():
            raise AuthorizationError(
                "No authorization confirmed. Pass --i-am-authorized, set "
                "RECONX_AUTHORIZED=1, or run interactively."
            )
        tgt = ", ".join(targets) if not isinstance(targets, str) else targets
        print(f"\nTarget scope: {tgt}", file=sys.stderr)
        answer = input(
            "Do you have explicit authorization to test this scope? "
            "Type 'yes' to continue: "
        ).strip().lower()
        granted = answer in ("yes", "y")

    if not granted:
        raise AuthorizationError("Authorization not confirmed — aborting.")

    _write_audit(targets, {"authorized": True})
    return True
