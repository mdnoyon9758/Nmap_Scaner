"""
Offline unit tests for the ReconX *network* modules.

Every test here mocks out sockets and HTTP so the suite is fully
self-contained: it never opens a socket, resolves a name, or contacts a
real host. This is what lets the toolkit's network code be exercised in CI
without scanning anyone.

Run with:  python3 -m unittest discover -s tests
"""

import os
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconx.core import net
from reconx.modules import (
    portscan, http_headers, dns_enum, tls_info,
    tech_fingerprint, web_recon, subdomains,
)


# ---------------------------------------------------------------------------
# Helpers: fakes that stand in for real network objects
# ---------------------------------------------------------------------------

def _dns_a_response(name="example.com", ip=(1, 2, 3, 4)):
    """Build a minimal well-formed DNS response with one A answer."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = net._encode_qname(name) + struct.pack(">HH", 1, 1)
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes(ip))
    return header + question + answer


class FakeTCPSocket:
    """A context-manager stand-in for a TCP socket used by the port scanner."""

    def __init__(self, open_ports, banners=None):
        self._open_ports = set(open_ports)
        self._banners = banners or {}
        self._port = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, _timeout):
        pass

    def connect_ex(self, addr):
        self._port = addr[1]
        return 0 if addr[1] in self._open_ports else 1

    def sendall(self, _data):
        pass

    def recv(self, _n):
        return self._banners.get(self._port, b"")


class FakeHTTPResponse:
    """Stand-in for the object returned by urllib.request.urlopen()."""

    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self._headers = headers or {}
        self._body = body

    @property
    def headers(self):
        return self._headers

    def read(self, _max_bytes=None):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Headers(dict):
    """dict whose .items() mirrors http.client message behaviour."""


# ---------------------------------------------------------------------------
# reconx.core.net — the shared plumbing, mocked at the socket/urllib layer
# ---------------------------------------------------------------------------

class TestNetHttpRequest(unittest.TestCase):
    def test_http_request_parses_response(self):
        headers = _Headers({"Server": "nginx", "X-Test": "1"})
        fake = FakeHTTPResponse(200, headers, b"hello")
        with mock.patch.object(net.urllib.request, "urlopen",
                               return_value=fake) as urlopen:
            status, hdrs, body = net.http_request("http://example.com")
        self.assertEqual(status, 200)
        self.assertEqual(hdrs["Server"], "nginx")
        self.assertEqual(body, b"hello")
        # Confirm we never reached out for real: urlopen was the only I/O.
        self.assertTrue(urlopen.called)

    def test_https_uses_tls_context(self):
        fake = FakeHTTPResponse(204, _Headers({}), b"")
        with mock.patch.object(net.urllib.request, "urlopen",
                               return_value=fake) as urlopen:
            net.http_request("https://example.com", verify_tls=False)
        # A TLS context must have been passed for an https URL.
        _, kwargs = urlopen.call_args
        self.assertIsNotNone(kwargs.get("context"))


class TestNetDnsQuery(unittest.TestCase):
    def test_dns_query_a_record(self):
        packet = _dns_a_response("example.com", (93, 184, 216, 34))
        fake_sock = mock.MagicMock()
        fake_sock.recvfrom.return_value = (packet, ("1.1.1.1", 53))
        with mock.patch.object(net.socket, "socket", return_value=fake_sock):
            answers = net.dns_query("example.com", "A", resolver="1.1.1.1")
        self.assertEqual(answers, ["93.184.216.34"])
        fake_sock.sendto.assert_called_once()

    def test_dns_query_rejects_bad_type(self):
        with self.assertRaises(ValueError):
            net.dns_query("example.com", "BOGUS")

    def test_dns_query_timeout_returns_empty(self):
        fake_sock = mock.MagicMock()
        fake_sock.recvfrom.side_effect = OSError("boom")
        with mock.patch.object(net.socket, "socket", return_value=fake_sock):
            self.assertEqual(net.dns_query("example.com", "A",
                                           resolver="1.1.1.1"), [])


class TestNetResolveHost(unittest.TestCase):
    def test_resolve_hostname(self):
        with mock.patch.object(net.socket, "gethostbyname",
                               return_value="10.0.0.5") as g:
            self.assertEqual(net.resolve_host("example.com"), "10.0.0.5")
            g.assert_called_once()

    def test_resolve_ip_passthrough(self):
        # An IP should short-circuit without any DNS call.
        with mock.patch.object(net.socket, "gethostbyname") as g:
            self.assertEqual(net.resolve_host("8.8.8.8"), "8.8.8.8")
            g.assert_not_called()

    def test_resolve_failure_returns_none(self):
        import socket as _socket
        with mock.patch.object(net.socket, "gethostbyname",
                               side_effect=_socket.gaierror):
            self.assertIsNone(net.resolve_host("nope.invalid"))


# ---------------------------------------------------------------------------
# portscan
# ---------------------------------------------------------------------------

class TestPortScanModule(unittest.TestCase):
    def _run(self, open_ports, banners=None, ports="22,80,3306"):
        mod = portscan.PortScanModule(threads=4, ports=ports)
        factory = lambda *a, **k: FakeTCPSocket(open_ports, banners)
        with mock.patch.object(portscan, "resolve_host",
                               return_value="10.0.0.1"), \
                mock.patch.object(portscan.socket, "socket", factory):
            return mod.run("example.com")

    def test_reports_open_ports(self):
        res = self._run({22, 80}, banners={22: b"SSH-2.0-OpenSSH"})
        titles = [f.title for f in res.findings]
        self.assertTrue(any("22/tcp open" in t for t in titles))
        self.assertTrue(any("80/tcp open" in t for t in titles))
        self.assertFalse(any("3306/tcp open" in t for t in titles))

    def test_risky_service_flagged_medium(self):
        res = self._run({3306})
        mysql = [f for f in res.findings if "3306/tcp" in f.title]
        self.assertEqual(mysql[0].severity, "medium")

    def test_no_open_ports(self):
        res = self._run(set())
        self.assertTrue(any("No open TCP ports" in f.title
                            for f in res.findings))

    def test_unresolvable_target_errors(self):
        mod = portscan.PortScanModule(threads=2, ports="80")
        with mock.patch.object(portscan, "resolve_host", return_value=None):
            res = mod.run("nope.invalid")
        self.assertIn("Could not resolve", res.error or "")


# ---------------------------------------------------------------------------
# http_headers
# ---------------------------------------------------------------------------

class TestHttpHeadersModule(unittest.TestCase):
    def test_flags_missing_security_headers(self):
        mod = http_headers.HttpHeadersModule()
        with mock.patch.object(http_headers, "http_request",
                               return_value=(200, {"Server": "nginx"}, b"")):
            res = mod.run("example.com")
        titles = [f.title for f in res.findings]
        self.assertTrue(any("HSTS not set" in t for t in titles))
        self.assertTrue(any("CSP not set" in t for t in titles))
        self.assertTrue(any("Information disclosure via 'server'" in t
                            for t in titles))

    def test_present_headers_not_flagged(self):
        headers = {
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        mod = http_headers.HttpHeadersModule()
        with mock.patch.object(http_headers, "http_request",
                               return_value=(200, headers, b"")):
            res = mod.run("example.com")
        titles = [f.title for f in res.findings]
        self.assertFalse(any("not set" in t for t in titles))

    def test_request_failure_sets_error(self):
        mod = http_headers.HttpHeadersModule()
        with mock.patch.object(http_headers, "http_request",
                               side_effect=Exception("dead")):
            res = mod.run("https://example.com")
        self.assertIn("Request failed", res.error or "")


# ---------------------------------------------------------------------------
# dns_enum
# ---------------------------------------------------------------------------

class TestDnsEnumModule(unittest.TestCase):
    def test_reports_records(self):
        def fake_query(name, rtype, **kw):
            if rtype == "A":
                return ["93.184.216.34"]
            if rtype == "TXT":
                return ["v=spf1 -all"]
            return []
        mod = dns_enum.DnsEnumModule()
        with mock.patch.object(dns_enum, "dns_query", side_effect=fake_query):
            res = mod.run("example.com")
        titles = [f.title for f in res.findings]
        self.assertTrue(any("A records" in t for t in titles))

    def test_missing_spf_and_dmarc_flagged(self):
        def fake_query(name, rtype, **kw):
            # TXT present but no SPF; no DMARC anywhere.
            if rtype == "TXT" and not name.startswith("_dmarc"):
                return ["google-site-verification=abc"]
            return []
        mod = dns_enum.DnsEnumModule()
        with mock.patch.object(dns_enum, "dns_query", side_effect=fake_query):
            res = mod.run("example.com")
        titles = [f.title for f in res.findings]
        self.assertTrue(any("No SPF record" in t for t in titles))
        self.assertTrue(any("No DMARC record" in t for t in titles))

    def test_ip_target_rejected(self):
        mod = dns_enum.DnsEnumModule()
        res = mod.run("8.8.8.8")
        self.assertIn("expects a hostname", res.error or "")


# ---------------------------------------------------------------------------
# tech_fingerprint
# ---------------------------------------------------------------------------

class TestTechFingerprintModule(unittest.TestCase):
    def test_detects_from_headers_and_body(self):
        headers = {"Server": "Apache", "X-Powered-By": "PHP/8.1",
                   "Set-Cookie": "PHPSESSID=abc"}
        body = b"<html><meta name='generator' content='WordPress 6.4'>" \
               b"wp-content/themes</html>"
        mod = tech_fingerprint.TechFingerprintModule()
        with mock.patch.object(tech_fingerprint, "http_request",
                               return_value=(200, headers, body)):
            res = mod.run("example.com")
        detail = "\n".join(f.detail or "" for f in res.findings)
        self.assertIn("WordPress", detail)
        self.assertIn("PHP", detail)

    def test_request_failure_sets_error(self):
        mod = tech_fingerprint.TechFingerprintModule()
        with mock.patch.object(tech_fingerprint, "http_request",
                               side_effect=Exception("dead")):
            res = mod.run("example.com")
        self.assertIn("Request failed", res.error or "")


# ---------------------------------------------------------------------------
# web_recon
# ---------------------------------------------------------------------------

class TestWebReconModule(unittest.TestCase):
    def test_flags_exposed_git_config(self):
        def fake_http(url, method="GET", **kw):
            if url.endswith("/.git/config"):
                return 200, {}, b"[core]\n"
            if url.endswith("/robots.txt"):
                return 200, {}, b"User-agent: *"
            return 404, {}, b""
        mod = web_recon.WebReconModule(threads=4)
        with mock.patch.object(web_recon, "http_request",
                               side_effect=fake_http):
            res = mod.run("example.com")
        titles = [f.title for f in res.findings]
        self.assertTrue(any("Exposed Git repository config" in t
                            for t in titles))
        git = [f for f in res.findings if "Git repository config" in f.title]
        self.assertEqual(git[0].severity, "high")

    def test_clean_site_reports_nothing_found(self):
        mod = web_recon.WebReconModule(threads=4)
        with mock.patch.object(web_recon, "http_request",
                               return_value=(404, {}, b"")):
            res = mod.run("example.com")
        self.assertTrue(any("No well-known or exposed" in f.title
                            for f in res.findings))


# ---------------------------------------------------------------------------
# subdomains
# ---------------------------------------------------------------------------

class TestSubdomainModule(unittest.TestCase):
    def test_ct_and_wordlist_merge(self):
        ct_body = b'[{"name_value": "www.example.com\\napi.example.com"}]'

        def fake_http(url, **kw):
            return 200, {}, ct_body

        def fake_dns(host, rtype, **kw):
            return ["10.0.0.9"] if host.startswith("mail.") else []

        mod = subdomains.SubdomainModule(threads=4, words=["mail", "ftp"])
        with mock.patch.object(subdomains, "http_request",
                               side_effect=fake_http), \
                mock.patch.object(subdomains, "dns_query",
                                  side_effect=fake_dns):
            res = mod.run("example.com")
        detail = "\n".join(f.detail or "" for f in res.findings)
        self.assertIn("www.example.com", detail)
        self.assertIn("mail.example.com", detail)

    def test_ip_target_rejected(self):
        mod = subdomains.SubdomainModule()
        res = mod.run("8.8.8.8")
        self.assertIn("expects a domain", res.error or "")


# ---------------------------------------------------------------------------
# tls_info
# ---------------------------------------------------------------------------

class _FakeSSLSock:
    def __init__(self, proto, cert):
        self._proto = proto
        self._cert = cert

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def version(self):
        return self._proto

    def getpeercert(self, binary_form=False):
        return self._cert


class _FakeCtx:
    def __init__(self, proto, cert):
        self._proto = proto
        self._cert = cert
        self.check_hostname = True
        self.verify_mode = None

    def wrap_socket(self, sock, server_hostname=None):
        return _FakeSSLSock(self._proto, self._cert)


class _FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestTlsInfoModule(unittest.TestCase):
    def _patch(self, proto, cert):
        return (
            mock.patch.object(tls_info.ssl, "create_default_context",
                              side_effect=lambda *a, **k: _FakeCtx(proto, cert)),
            mock.patch.object(tls_info.socket, "create_connection",
                              return_value=_FakeConn()),
        )

    def test_reports_certificate_and_protocol(self):
        cert = {
            "subject": [(("commonName", "example.com"),)],
            "issuer": [(("organizationName", "Let's Encrypt"),
                        ("commonName", "R3"),)],
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Jan  1 00:00:00 2999 GMT",
            "subjectAltName": [("DNS", "example.com")],
        }
        ctx_patch, conn_patch = self._patch("TLSv1.3", cert)
        with ctx_patch, conn_patch:
            res = tls_info.TlsInfoModule().run("example.com")
        info = res.findings[0]
        self.assertIn("TLS on example.com:443", info.title)
        self.assertEqual(info.data["protocol"], "TLSv1.3")

    def test_deprecated_protocol_flagged(self):
        cert = {
            "subject": [(("commonName", "old.example.com"),)],
            "issuer": [(("commonName", "CA"),)],
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Jan  1 00:00:00 2999 GMT",
            "subjectAltName": [],
        }
        ctx_patch, conn_patch = self._patch("TLSv1", cert)
        with ctx_patch, conn_patch:
            res = tls_info.TlsInfoModule().run("old.example.com")
        self.assertTrue(any("Deprecated TLS protocol" in f.title
                            for f in res.findings))

    def test_connection_failure_sets_error(self):
        with mock.patch.object(tls_info.socket, "create_connection",
                               side_effect=OSError("refused")):
            res = tls_info.TlsInfoModule().run("example.com")
        self.assertIn("TLS connection failed", res.error or "")


if __name__ == "__main__":
    unittest.main()
