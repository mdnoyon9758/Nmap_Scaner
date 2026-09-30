"""
Unified reporting for ReconX.

Every module emits results into a single Report object, which can then be
rendered as human-readable text, JSON (for tooling / pipelines), or a
self-contained HTML report suitable for handing to a client.
"""

from __future__ import annotations

import json
import html
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLORS = {
    "info": "#3b82f6", "low": "#22c55e", "medium": "#eab308",
    "high": "#f97316", "critical": "#ef4444",
}


@dataclass
class Finding:
    module: str
    title: str
    severity: str = "info"          # info|low|medium|high|critical
    target: str = ""
    detail: str = ""
    data: dict = field(default_factory=dict)


@dataclass
class ModuleResult:
    module: str
    target: str
    started: str = ""
    finished: str = ""
    findings: list = field(default_factory=list)
    error: str | None = None


class Report:
    def __init__(self, title: str = "ReconX Assessment"):
        self.title = title
        self.created = datetime.now(timezone.utc).isoformat()
        self.results: list[ModuleResult] = []

    def add(self, result: ModuleResult) -> None:
        self.results.append(result)

    # ---- iteration helpers ------------------------------------------------
    def all_findings(self) -> list[Finding]:
        out = []
        for r in self.results:
            out.extend(r.findings)
        return out

    def counts(self) -> dict:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.all_findings():
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    # ---- serialization ----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "created": self.created,
            "summary": self.counts(),
            "results": [
                {
                    "module": r.module,
                    "target": r.target,
                    "started": r.started,
                    "finished": r.finished,
                    "error": r.error,
                    "findings": [asdict(f) for f in r.findings],
                }
                for r in self.results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_text(self) -> str:
        lines = []
        lines.append("=" * 72)
        lines.append(f" {self.title}")
        lines.append(f" Generated: {self.created}")
        lines.append("=" * 72)
        c = self.counts()
        lines.append(
            " Summary: "
            + "  ".join(f"{k}={c[k]}" for k in
                        ["critical", "high", "medium", "low", "info"])
        )
        for r in self.results:
            lines.append("")
            lines.append("-" * 72)
            lines.append(f" [{r.module}] target={r.target}")
            if r.error:
                lines.append(f"   ERROR: {r.error}")
            if not r.findings:
                lines.append("   (no findings)")
            for f in sorted(r.findings,
                            key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)):
                lines.append(f"   [{f.severity.upper():8}] {f.title}")
                if f.detail:
                    for dl in f.detail.splitlines():
                        lines.append(f"            {dl}")
        lines.append("")
        lines.append("=" * 72)
        return "\n".join(lines)

    def to_html(self) -> str:
        c = self.counts()
        rows = []
        for r in self.results:
            fbits = []
            for f in sorted(r.findings,
                            key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)):
                color = SEVERITY_COLORS.get(f.severity, "#888")
                fbits.append(
                    f'<div class="finding">'
                    f'<span class="sev" style="background:{color}">'
                    f'{html.escape(f.severity.upper())}</span> '
                    f'<strong>{html.escape(f.title)}</strong>'
                    + (f'<pre>{html.escape(f.detail)}</pre>' if f.detail else "")
                    + '</div>'
                )
            err = (f'<p class="err">Error: {html.escape(r.error)}</p>'
                   if r.error else "")
            rows.append(
                f'<section><h2>{html.escape(r.module)} '
                f'<small>{html.escape(r.target)}</small></h2>{err}'
                + ("".join(fbits) or "<p>(no findings)</p>")
                + "</section>"
            )
        summary = "".join(
            f'<span class="pill" style="background:{SEVERITY_COLORS[k]}">'
            f'{k}: {c[k]}</span>'
            for k in ["critical", "high", "medium", "low", "info"]
        )
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(self.title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0;
          background:#0f1117; color:#e6e6e6; }}
  header {{ padding:24px; background:#161a23; border-bottom:1px solid #262b36; }}
  h1 {{ margin:0 0 8px; font-size:20px; }}
  .meta {{ color:#8b93a7; font-size:13px; }}
  .pill {{ display:inline-block; padding:3px 10px; border-radius:12px;
           color:#0b0b0b; font-size:12px; font-weight:600; margin:4px 6px 0 0; }}
  main {{ padding:16px 24px; max-width:1000px; margin:0 auto; }}
  section {{ background:#161a23; border:1px solid #262b36; border-radius:10px;
             padding:16px; margin:16px 0; }}
  h2 {{ font-size:16px; margin:0 0 12px; }}
  h2 small {{ color:#8b93a7; font-weight:400; }}
  .finding {{ padding:8px 0; border-top:1px solid #21262f; }}
  .sev {{ display:inline-block; padding:2px 8px; border-radius:6px;
          color:#0b0b0b; font-size:11px; font-weight:700; margin-right:8px; }}
  pre {{ background:#0b0e14; padding:10px; border-radius:6px; overflow:auto;
         font-size:12px; margin:8px 0 0; white-space:pre-wrap; }}
  .err {{ color:#ef4444; }}
</style></head><body>
<header>
  <h1>{html.escape(self.title)}</h1>
  <div class="meta">Generated {html.escape(self.created)}</div>
  <div>{summary}</div>
  <div class="meta" style="margin-top:12px">For authorized security
   assessment only.</div>
</header>
<main>{"".join(rows)}</main>
</body></html>"""
