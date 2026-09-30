"""
ReconX unified command-line interface.

Examples
--------
  # Full authorized recon of a domain, HTML report to disk
  reconx example.com --profile recon --i-am-authorized \\
          --format html --output report.html

  # Just a port scan of an IP (no nmap needed)
  reconx 203.0.113.10 --modules portscan --ports top --i-am-authorized

  # Web-app surface review with a polite rate limit
  reconx https://example.com --profile web --rate 5 --i-am-authorized

  # List everything available
  reconx --list
"""

from __future__ import annotations

import sys
import argparse

from reconx import __version__
from reconx.core.authorization import confirm_authorization, AuthorizationError
from reconx.core.net import expand_targets, DEFAULT_TIMEOUT
from reconx.toolkit import Toolkit, PROFILES


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — self-contained recon & security assessment "
                    "toolkit for AUTHORIZED testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("targets", nargs="*",
                   help="hostnames, IPs, URLs, or CIDR ranges")
    p.add_argument("--modules", "-m", nargs="+",
                   help="modules or profiles to run "
                        f"(profiles: {', '.join(PROFILES)}; or 'all')")
    p.add_argument("--profile", "-p", choices=list(PROFILES),
                   help="shortcut for a module group (default: recon)")
    p.add_argument("--ports", help="port spec for portscan: top|all|22,80|1-1024")
    p.add_argument("--nmap-scan-type",
                   choices=["quick", "intense", "service", "ping"],
                   default="service",
                   help="scan type for the optional nmap module")
    p.add_argument("--wordlist", help="subdomain wordlist file (one per line)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"per-connection timeout seconds (default {DEFAULT_TIMEOUT})")
    p.add_argument("--rate", type=float, default=0.0,
                   help="max operations/sec (0 = unlimited; be considerate)")
    p.add_argument("--threads", "-t", type=int, default=50,
                   help="concurrency (default 50)")
    p.add_argument("--no-verify-tls", action="store_true",
                   help="do not verify TLS certs on HTTP requests")
    p.add_argument("--format", "-f", choices=["text", "json", "html"],
                   default="text", help="report format (default text)")
    p.add_argument("--output", "-o", help="write report to this file")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="assert you have permission to test the targets")
    p.add_argument("--yes", "-y", action="store_true",
                   help="assume yes to authorization prompt (scripting)")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="suppress banner and progress")
    p.add_argument("--list", action="store_true",
                   help="list available modules and profiles, then exit")
    p.add_argument("--version", action="version",
                   version=f"ReconX {__version__}")
    return p


def _load_wordlist(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip()
                    and not ln.startswith("#")]
    except OSError as exc:
        print(f"Could not read wordlist: {exc}", file=sys.stderr)
        return None


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list:
        tk = Toolkit()
        print("Profiles:")
        for name, mods in PROFILES.items():
            print(f"  {name:8} -> {', '.join(mods)}")
        print("\nModules:")
        for name, desc in tk.available().items():
            print(f"  {name:12} {desc}")
        return 0

    if not args.targets:
        build_parser().print_help()
        return 2

    # Expand CIDRs into concrete targets.
    targets: list[str] = []
    try:
        for t in args.targets:
            targets.extend(expand_targets(t))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    # Authorization gate — this is not optional.
    try:
        confirm_authorization(targets, authorized=args.i_am_authorized,
                              assume_yes=args.yes, quiet=args.quiet)
    except AuthorizationError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 3

    opts = {
        "ports": args.ports,
        "verify_tls": not args.no_verify_tls,
        "nmap_scan_type": args.nmap_scan_type,
    }
    if args.wordlist:
        words = _load_wordlist(args.wordlist)
        if words:
            opts["words"] = words

    modules = args.modules or ([args.profile] if args.profile else None)

    tk = Toolkit(timeout=args.timeout, rate=args.rate,
                 threads=args.threads, **opts)

    def progress(target, module):
        if not args.quiet:
            print(f"[*] {module} -> {target}", file=sys.stderr)

    report = tk.run(targets, modules=modules, progress=progress)

    if args.format == "json":
        rendered = report.to_json()
    elif args.format == "html":
        rendered = report.to_html()
    else:
        rendered = report.to_text()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        if not args.quiet:
            print(f"\n[+] Report written to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    # Exit non-zero if anything medium+ was found (handy for CI gates).
    counts = report.counts()
    if counts.get("critical") or counts.get("high") or counts.get("medium"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
