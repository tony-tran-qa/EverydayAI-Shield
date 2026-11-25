"""
Tests for checks/check_network_beaconing.py - suspicious-domain detection, known-safe
matching on domain boundaries (no lookalikes), netstat/tasklist parsing.
DNS, netstat and tasklist are stubbed.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_network_beaconing", ROOT / "checks" / "check_network_beaconing.py")
nb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nb)

CONFIG = {"checks": {"network_beaconing": {"enabled": True, "severity": "HIGH"}},
          "known_ai_processes": ["node", "claude"], "suspicious_domains": []}


def conn(host_ip="52.1.2.3", proc="node.exe", port="443"):
    return {"process": proc, "pid": "10", "local": "10.0.0.5:50000",
            "remote_ip": host_ip, "remote_port": port, "remote_host": ""}


def run_with(monkeypatch, conns, hostnames=None, config=CONFIG):
    """hostnames maps remote_ip -> reverse-DNS name; unmapped IPs resolve to themselves."""
    hostnames = hostnames or {}
    monkeypatch.setattr(nb, "get_ai_connections", lambda procs: conns)
    monkeypatch.setattr(nb, "reverse_lookup", lambda ip: hostnames.get(ip, ip))
    return nb.run(config)


class TestIsKnownSafe:
    @pytest.mark.parametrize("host", [
        "api.anthropic.com", "anthropic.com", "claude.ai", "registry.npmjs.org",
        "ec2-1-2-3-4.compute-1.amazonaws.com", "localhost", "127.0.0.1", "GITHUB.COM", "github.com.",
    ])
    def test_real_and_subdomain_hosts_are_safe(self, host):
        assert nb.is_known_safe(host)

    @pytest.mark.parametrize("host", [
        "anthropic.com.evil.net", "notgithub.com", "evil-anthropic.com", "claude.ai.attacker.io",
        "pypi.org.example.ru", "example.com", "", None,
    ])
    def test_lookalikes_and_unknowns_are_not_safe(self, host):
        assert not nb.is_known_safe(host)


class TestRunFindings:
    def test_no_connections_passes(self, monkeypatch):
        assert run_with(monkeypatch, []).status == "PASS"

    def test_known_safe_host_passes(self, monkeypatch):
        r = run_with(monkeypatch, [conn("1.1.1.1")], {"1.1.1.1": "api.anthropic.com"})
        assert r.status == "PASS"

    @pytest.mark.parametrize("host", ["pastebin.com", "abc.ngrok-free.app", "webhook.site", "x.serveo.net"])
    def test_suspicious_domains_fail(self, monkeypatch, host):
        r = run_with(monkeypatch, [conn("2.2.2.2")], {"2.2.2.2": host})
        assert r.status == "FAIL" and "node.exe" in "\n".join(r.details)

    def test_config_suspicious_domain_honored(self, monkeypatch):
        cfg = dict(CONFIG, suspicious_domains=["evil-exfil.example"])
        r = run_with(monkeypatch, [conn("2.2.2.2")], {"2.2.2.2": "drop.evil-exfil.example"}, cfg)
        assert r.status == "FAIL"

    def test_unrecognized_hostname_warns(self, monkeypatch):
        r = run_with(monkeypatch, [conn("3.3.3.3")], {"3.3.3.3": "cdn.some-vendor.net"})
        assert r.status == "WARN"

    def test_raw_ip_warns(self, monkeypatch):
        r = run_with(monkeypatch, [conn("4.4.4.4")])
        assert r.status == "WARN" and any("raw IP" in d for d in r.details)

    def test_lookalike_of_safe_domain_warns_not_passes(self, monkeypatch):
        r = run_with(monkeypatch, [conn("5.5.5.5")], {"5.5.5.5": "anthropic.com.evil.net"})
        assert r.status == "WARN"

    def test_fail_beats_warn(self, monkeypatch):
        r = run_with(monkeypatch, [conn("4.4.4.4"), conn("2.2.2.2")], {"2.2.2.2": "pastebin.com"})
        assert r.status == "FAIL"

    def test_enumeration_error(self, monkeypatch):
        r = run_with(monkeypatch, [{"error": "netstat failed"}])
        assert r.status == "ERROR"


NETSTAT = """
  Proto  Local Address          Foreign Address        State           PID
  TCP    10.0.0.5:50001         52.1.2.3:443           ESTABLISHED     1234
  TCP    10.0.0.5:50002         52.9.9.9:443           ESTABLISHED     5678
  TCP    127.0.0.1:50003        127.0.0.1:5173         ESTABLISHED     1234
  TCP    10.0.0.5:50004         [2600:1::1]:443        CLOSE_WAIT      1234
  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       1234
"""
TASKLIST = '"node.exe","1234","Console","1","50,000 K"\n"chrome.exe","5678","Console","1","90,000 K"\n'


class TestConnectionParsing:
    @pytest.fixture(autouse=True)
    def fake(self, monkeypatch):
        class R:
            def __init__(self, out):
                self.stdout = out

        monkeypatch.setattr(nb.subprocess, "run",
                            lambda cmd, **k: R(NETSTAT if cmd[0] == "netstat" else TASKLIST))

    def test_keeps_only_ai_process_external_connections(self):
        conns = nb.get_ai_connections(["node"])
        assert {c["remote_ip"] for c in conns} == {"52.1.2.3", "2600:1::1"}

    def test_other_processes_dropped(self):
        assert all(c["process"] == "node.exe" for c in nb.get_ai_connections(["node"]))

    def test_localhost_and_listening_dropped(self):
        ips = {c["remote_ip"] for c in nb.get_ai_connections(["node"])}
        assert "127.0.0.1" not in ips and "0.0.0.0" not in ips

    def test_ports_and_pids_captured(self):
        c = [c for c in nb.get_ai_connections(["node"]) if c["remote_ip"] == "52.1.2.3"][0]
        assert c["remote_port"] == "443" and c["pid"] == "1234"

    def test_no_ai_processes_configured_matches_nothing(self):
        assert nb.get_ai_connections(["definitely-not-running"]) == []

    def test_failure_returns_error_entry(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("denied")

        monkeypatch.setattr(nb.subprocess, "run", boom)
        assert "error" in nb.get_ai_connections(["node"])[0]


def test_reverse_lookup_falls_back_to_ip(monkeypatch):
    def boom(ip):
        raise OSError("no ptr")

    monkeypatch.setattr(nb.socket, "gethostbyaddr", boom)
    assert nb.reverse_lookup("9.9.9.9") == "9.9.9.9"


class TestRawIpAndExtraDomains:
    def _conn(self, ip="2607:6bc0::10"):
        return [{"process": "claude.exe", "pid": "1", "remote_ip": ip, "remote_port": 443}]

    def test_raw_ip_of_vendor_host_is_accepted(self, monkeypatch):
        monkeypatch.setattr(nb, "get_ai_connections", lambda procs: self._conn())
        monkeypatch.setattr(nb, "reverse_lookup", lambda ip: ip)
        monkeypatch.setattr(nb, "resolve_safe_ips", lambda: {"2607:6bc0::10"})
        r = nb.run({})
        assert r.status == "PASS"
        assert any("known AI vendor host" in d for d in r.details)

    def test_raw_ip_not_in_vendor_set_still_warns(self, monkeypatch):
        monkeypatch.setattr(nb, "get_ai_connections", lambda procs: self._conn("203.0.113.9"))
        monkeypatch.setattr(nb, "reverse_lookup", lambda ip: ip)
        monkeypatch.setattr(nb, "resolve_safe_ips", lambda: {"2607:6bc0::10"})
        assert nb.run({}).status == "WARN"

    def test_ipv6_spelling_differences_still_match(self, monkeypatch):
        monkeypatch.setattr(nb, "get_ai_connections", lambda procs: self._conn("2607:6BC0:0:0:0:0:0:10"))
        monkeypatch.setattr(nb, "reverse_lookup", lambda ip: ip)
        monkeypatch.setattr(nb, "resolve_safe_ips", lambda: {"2607:6bc0::10"})
        assert nb.run({}).status == "PASS"

    def test_vendor_ip_lookup_only_for_raw_ips(self, monkeypatch):
        calls = []
        monkeypatch.setattr(nb, "get_ai_connections", lambda procs: [
            {"process": "claude.exe", "pid": "1", "remote_ip": "1.2.3.4", "remote_port": 443}])
        monkeypatch.setattr(nb, "reverse_lookup", lambda ip: "api.anthropic.com")
        monkeypatch.setattr(nb, "resolve_safe_ips", lambda: calls.append(1) or set())
        assert nb.run({}).status == "PASS"
        assert calls == []

    def test_resolve_safe_ips_collects_and_normalizes(self, monkeypatch):
        monkeypatch.setattr(nb.socket, "getaddrinfo", lambda host, port: [
            (0, 0, 0, "", ("2607:6BC0:0:0:0:0:0:10", 443, 0, 0)), (0, 0, 0, "", ("160.79.104.10", 443))])
        assert nb.resolve_safe_ips() == {"2607:6bc0::10", "160.79.104.10"}

    def test_resolve_safe_ips_survives_dns_failure(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("no dns")
        monkeypatch.setattr(nb.socket, "getaddrinfo", boom)
        assert nb.resolve_safe_ips() == set()

    def test_extra_domains_from_config_are_honored(self, monkeypatch):
        monkeypatch.setattr(nb, "get_ai_connections", lambda procs: [
            {"process": "claude.exe", "pid": "1", "remote_ip": "54.1.1.1", "remote_port": 443}])
        monkeypatch.setattr(nb, "reverse_lookup", lambda ip: "ip-54-1-1-1.stripe.com")
        assert nb.run({}).status == "WARN"
        assert nb.run({"known_safe_domains": ["stripe.com"]}).status == "PASS"

    def test_extra_domains_still_use_boundary_matching(self):
        assert nb.is_known_safe("ip-1.stripe.com", ["stripe.com"])
        assert not nb.is_known_safe("stripe.com.evil.net", ["stripe.com"])
        assert not nb.is_known_safe("notstripe.com", ["stripe.com"])
