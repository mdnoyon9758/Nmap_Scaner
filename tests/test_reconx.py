"""
Offline unit tests for ReconX core logic (no network required).

Run with:  python3 -m unittest discover -s tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconx.core import net
from reconx.core.report import Report, ModuleResult, Finding
from reconx.core.authorization import confirm_authorization, AuthorizationError
from reconx.modules.portscan import parse_ports
from reconx.toolkit import Toolkit, PROFILES


class TestPortSpec(unittest.TestCase):
    def test_default_is_top(self):
        self.assertGreater(len(parse_ports(None)), 10)

    def test_range_and_list(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(parse_ports("1-3"), [1, 2, 3])

    def test_dedupe_and_sort(self):
        self.assertEqual(parse_ports("80,22,80"), [22, 80])


class TestTargets(unittest.TestCase):
    def test_cidr_expansion(self):
        self.assertEqual(net.expand_targets("192.168.0.0/30"),
                         ["192.168.0.1", "192.168.0.2"])

    def test_cidr_guard(self):
        with self.assertRaises(ValueError):
            net.expand_targets("10.0.0.0/8")

    def test_is_ip(self):
        self.assertTrue(net.is_ip("8.8.8.8"))
        self.assertFalse(net.is_ip("example.com"))


class TestDnsParsing(unittest.TestCase):
    def test_parse_a_record(self):
        # Hand-crafted response: 1 question, 1 answer A -> 93.184.216.34
        import struct
        header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        question = net._encode_qname("example.com") + struct.pack(">HH", 1, 1)
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4)
                  + bytes([93, 184, 216, 34]))
        packet = header + question + answer
        self.assertEqual(net._parse_dns_answers(packet), ["93.184.216.34"])


class TestReport(unittest.TestCase):
    def _sample(self):
        rep = Report("t")
        r = ModuleResult(module="m", target="x")
        r.findings.append(Finding(module="m", title="high thing",
                                  severity="high", target="x"))
        r.findings.append(Finding(module="m", title="info thing",
                                  severity="info", target="x"))
        rep.add(r)
        return rep

    def test_counts(self):
        self.assertEqual(self._sample().counts()["high"], 1)

    def test_formats(self):
        rep = self._sample()
        self.assertIn("high thing", rep.to_text())
        import json
        self.assertEqual(json.loads(rep.to_json())["summary"]["high"], 1)
        self.assertIn("<html", rep.to_html())


class TestAuthorization(unittest.TestCase):
    def test_flag_grants(self):
        self.assertTrue(confirm_authorization(["x"], authorized=True, quiet=True))

    def test_env_grants(self):
        os.environ["RECONX_AUTHORIZED"] = "1"
        try:
            self.assertTrue(confirm_authorization(["x"], quiet=True))
        finally:
            del os.environ["RECONX_AUTHORIZED"]


class TestToolkit(unittest.TestCase):
    def test_profiles_resolve(self):
        tk = Toolkit()
        for prof in PROFILES:
            self.assertTrue(tk.resolve_modules(prof))

    def test_unknown_module_raises(self):
        with self.assertRaises(ValueError):
            Toolkit().resolve_modules("does-not-exist")

    def test_registry_complete(self):
        tk = Toolkit()
        for m in ["portscan", "dns", "subdomains", "whois", "headers",
                  "tls", "tech", "web", "nmap"]:
            self.assertIn(m, tk.registry)


if __name__ == "__main__":
    unittest.main()
