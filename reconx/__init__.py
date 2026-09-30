"""
ReconX — a self-contained, cross-platform reconnaissance and security
assessment toolkit for authorized penetration testing and bug-bounty work.

Everything here is built on the Python standard library so it runs anywhere
Python runs (Windows, macOS, Linux, Android/Termux) without needing a
separate Linux box or external binaries. Optional integrations (e.g. nmap)
are used only when present.

Intended strictly for use against systems you own or are explicitly
authorized to test. See reconx.core.authorization.
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
