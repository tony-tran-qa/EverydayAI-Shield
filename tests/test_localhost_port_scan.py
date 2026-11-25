"""
Tests for checks/check_localhost_port_scan.py - netstat parsing, tunnel / all-interface
detection, Windows system-process allowances. netstat and tasklist are stubbed.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_localhost_port_scan", ROOT / "checks" / "check_localhost_port_scan.py")
lp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lp)

CONFIG = {"checks": {"localhost_port_scan": {"enabled": True, "severity": "HIGH"}}, "known_safe_ports": []}


def listener(port, pid="100", all_interfaces=False):
    addr = f"{'0.0.0.0' if all_interfaces else '127.0.0.1'}:{port}"
    return {"port": port, "pid": pid, "all_interfaces": all_interfaces, "addr": addr}


def run_with(monkeypatch, listeners, procs=None, config=CONFIG):
    """procs maps pid -> process name; unknown pids get 'unknown'."""
    procs = procs or {}
    monkeypatch.setattr(lp, "get_listening_ports", lambda: listeners)
    monkeypatch.setattr(lp, "get_process_name", lambda pid: procs.get(pid, "unknown"))
    return lp.run(config)


class TestFindings:
    def test_clean_machine_passes(self, monkeypatch):
        r = run_with(monkeypatch, [listener(3000), listener(8080)])
        assert r.status == "PASS" and "2 listeners" in r.message

    @pytest.mark.parametrize("port", [4040, 4041])
    def test_ngrok_ports_fail(self, monkeypatch, port):
        r = run_with(monkeypatch, [listener(port)])
        assert r.status == "FAIL" and "ngrok" in r.remediation

    def test_ngrok_process_on_any_port_fails(self, monkeypatch):
        r = run_with(monkeypatch, [listener(9999, pid="7")], procs={"7": "ngrok.exe"})
        assert r.status == "FAIL"

    def test_unknown_service_on_all_interfaces_fails(self, monkeypatch):
        r = run_with(monkeypatch, [listener(9999, all_interfaces=True)], procs={"100": "evil.exe"})
        assert r.status == "FAIL"

    def test_dual_stack_listener_counted_once(self, monkeypatch):
        v4 = listener(9999, pid="55", all_interfaces=True)
        v6 = dict(v4, addr="[::]:9999")
        r = run_with(monkeypatch, [v4, v6], procs={"55": "evil.exe"})
        assert r.status == "FAIL" and "1 suspicious" in r.message
        assert len([d for d in r.details if d.startswith("Port 9999")]) == 1

    def test_dual_stack_keeps_exposed_flag_from_either_binding(self, monkeypatch):
        loopback = listener(9999, pid="55", all_interfaces=False)
        exposed = listener(9999, pid="55", all_interfaces=True)
        assert run_with(monkeypatch, [loopback, exposed], procs={"55": "x.exe"}).status == "FAIL"

    def test_same_port_different_pids_both_evaluated(self, monkeypatch):
        r = run_with(monkeypatch, [listener(9999, pid="1", all_interfaces=True), listener(9999, pid="2", all_interfaces=True)],
                     procs={"1": "a.exe", "2": "b.exe"})
        assert "2 suspicious" in r.message

    def test_fail_details_explain_why(self, monkeypatch):
        r = run_with(monkeypatch, [listener(9999, all_interfaces=True)], procs={"100": "evil.exe"})
        assert any(d.startswith("[!]") and "9999" in d and "0.0.0.0" in d for d in r.details)

    def test_warn_details_explain_why(self, monkeypatch):
        r = run_with(monkeypatch, [listener(8888)], procs={"100": "python.exe"})
        assert r.status == "WARN" and any(d.startswith("[~]") and "8888" in d for d in r.details)

    def test_all_interfaces_on_safe_port_ok(self, monkeypatch):
        assert run_with(monkeypatch, [listener(3000, all_interfaces=True)]).status == "PASS"

    def test_all_interfaces_on_low_port_not_flagged(self, monkeypatch):
        assert run_with(monkeypatch, [listener(1000, all_interfaces=True)]).status == "PASS"

    def test_windows_system_process_on_all_interfaces_ok(self, monkeypatch):
        r = run_with(monkeypatch, [listener(49700, pid="9", all_interfaces=True)], procs={"9": "svchost.exe"})
        assert r.status == "PASS"

    def test_ai_tool_port_warns(self, monkeypatch):
        r = run_with(monkeypatch, [listener(8888)], procs={"100": "python.exe"})
        assert r.status == "WARN"

    def test_ephemeral_listener_from_unknown_process_warns(self, monkeypatch):
        r = run_with(monkeypatch, [listener(55555)], procs={"100": "mystery.exe"})
        assert r.status == "WARN"

    def test_ephemeral_listener_from_system_process_ok(self, monkeypatch):
        r = run_with(monkeypatch, [listener(55555)], procs={"100": "lsass.exe"})
        assert r.status == "PASS"

    def test_config_known_safe_ports_respected(self, monkeypatch):
        cfg = dict(CONFIG, known_safe_ports=[9999])
        r = run_with(monkeypatch, [listener(9999, all_interfaces=True)], procs={"100": "app.exe"}, config=cfg)
        assert r.status == "PASS"

    def test_enumeration_error_reported(self, monkeypatch):
        r = run_with(monkeypatch, [{"error": "netstat failed"}])
        assert r.status == "ERROR" and "netstat failed" in r.details[0]

    def test_fail_beats_warn(self, monkeypatch):
        r = run_with(monkeypatch, [listener(8888), listener(4040)])
        assert r.status == "FAIL"


NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1032
  TCP    127.0.0.1:5173         0.0.0.0:0              LISTENING       4488
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::1]:11434            [::]:0                 LISTENING       9001
  TCP    192.168.1.5:139        0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:50000        127.0.0.1:5173         ESTABLISHED     4488
  UDP    0.0.0.0:5353           *:*                                    1700
"""


class TestNetstatParsing:
    def _run(self, monkeypatch, stdout):
        class R:
            pass

        r = R()
        r.stdout = stdout
        monkeypatch.setattr(lp.subprocess, "run", lambda *a, **k: r)
        return lp.get_listening_ports()

    def test_parses_localhost_and_wildcard_listeners(self, monkeypatch):
        ports = {l["port"]: l for l in self._run(monkeypatch, NETSTAT)}
        assert set(ports) == {135, 5173, 445, 11434}

    def test_flags_all_interface_bindings(self, monkeypatch):
        ports = {l["port"]: l for l in self._run(monkeypatch, NETSTAT)}
        assert ports[135]["all_interfaces"] and ports[445]["all_interfaces"]
        assert not ports[5173]["all_interfaces"] and not ports[11434]["all_interfaces"]

    def test_ignores_non_listening_and_lan_addresses(self, monkeypatch):
        ports = {l["port"] for l in self._run(monkeypatch, NETSTAT)}
        assert 139 not in ports and 50000 not in ports and 5353 not in ports

    def test_pid_captured(self, monkeypatch):
        ports = {l["port"]: l for l in self._run(monkeypatch, NETSTAT)}
        assert ports[5173]["pid"] == "4488"

    def test_failure_returns_error_entry(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("no netstat")

        monkeypatch.setattr(lp.subprocess, "run", boom)
        assert "error" in lp.get_listening_ports()[0]


class TestProcessName:
    def test_parses_tasklist_csv(self, monkeypatch):
        class R:
            stdout = '"node.exe","4488","Console","1","50,000 K"\n'

        monkeypatch.setattr(lp.subprocess, "run", lambda *a, **k: R())
        assert lp.get_process_name("4488") == "node.exe"

    def test_unknown_on_failure(self, monkeypatch):
        def boom(*a, **k):
            raise OSError()

        monkeypatch.setattr(lp.subprocess, "run", boom)
        assert lp.get_process_name("1") == "unknown"
