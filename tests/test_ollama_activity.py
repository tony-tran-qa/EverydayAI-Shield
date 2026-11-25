"""
Tests for checks/check_ollama_activity.py - idle/loaded/VRAM/inference/version logic and
the CVE-2026-7482 version floor. The Ollama API, nvidia-smi, process list and logs are stubbed.
"""

import importlib.util
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_ollama_activity", ROOT / "checks" / "check_ollama_activity.py")
oa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oa)

CONFIG = {"checks": {"ollama_activity": {"enabled": True, "severity": "MEDIUM",
                                          "lookback_minutes": 30, "vram_idle_threshold_mib": 500}}}


def gin(minutes_ago, method="POST", path="/api/generate", status=200):
    ts = datetime.now() - timedelta(minutes=minutes_ago)
    return f'[GIN] {ts:%Y/%m/%d} - {ts:%H:%M:%S} | {status} |  1.2s | 127.0.0.1 | {method} "{path}"\n'


@pytest.fixture
def machine(monkeypatch, tmp_path):
    """Ollama running, idle, current version, no GPU, no logs. Tests override via the returned dict."""
    s = {"running": True, "ps": {"models": []}, "version": "0.40.15", "vram": None,
         "server_log": None, "app_log": None}
    monkeypatch.setattr(oa, "_ollama_running", lambda: s["running"])

    def api(endpoint, timeout=4):
        return {"/api/ps": s["ps"], "/api/version": {"version": s["version"]} if s["version"] else None}.get(endpoint)

    monkeypatch.setattr(oa, "_query_api", api)
    monkeypatch.setattr(oa, "_get_vram_used_mib", lambda: s["vram"])
    monkeypatch.setattr(oa, "_find_server_log", lambda: s["server_log"])
    monkeypatch.setattr(oa, "_find_app_log", lambda: s["app_log"])
    s["tmp"] = tmp_path
    return s


class TestSemver:
    @pytest.mark.parametrize("text,expected", [
        ("0.17.1", (0, 17, 1)), ("v0.40.15", (0, 40, 15)), ("ollama version is 0.5.7", (0, 5, 7)),
        ("garbage", None), ("", None), (None, None),
    ])
    def test_parse(self, text, expected):
        assert oa._parse_semver(text) == expected

    @pytest.mark.parametrize("ver,below", [
        ("0.17.0", True), ("0.16.9", True), ("0.9.0", True), ("0.17.1", False), ("0.17.2", False),
        ("0.40.15", False), ("1.0.0", False), (None, False), ("junk", False),
    ])
    def test_security_floor(self, ver, below):
        assert oa._below_security_floor(ver) is below


class TestRun:
    def test_not_running_passes(self, machine):
        machine["running"] = False
        r = oa.run(CONFIG)
        assert r.status == "PASS" and "not running" in r.message

    def test_idle_passes(self, machine):
        assert oa.run(CONFIG).status == "PASS"

    def test_loaded_model_warns(self, machine):
        machine["ps"] = {"models": [{"name": "llama3:8b", "size_vram": 6 * 1024**3, "expires_at": "soon"}]}
        r = oa.run(CONFIG)
        assert r.status == "WARN" and any("llama3:8b" in d for d in r.details)

    def test_api_ps_as_bare_list(self, machine):
        machine["ps"] = [{"name": "tiny", "size_vram": 0}]
        assert oa.run(CONFIG).status == "WARN"

    def test_api_unreachable_still_runs(self, machine):
        machine["ps"] = None
        r = oa.run(CONFIG)
        assert r.status == "PASS" and any("Could not reach" in d for d in r.details)

    def test_orphaned_vram_fails(self, machine):
        machine["vram"] = 4000
        r = oa.run(CONFIG)
        assert r.status == "FAIL" and "orphaned" in r.message

    def test_high_vram_with_loaded_model_is_not_an_anomaly(self, machine):
        machine["vram"] = 4000
        machine["ps"] = {"models": [{"name": "m", "size_vram": 1}]}
        assert oa.run(CONFIG).status == "WARN"  # warn for the loaded model only

    def test_low_vram_ok(self, machine):
        machine["vram"] = 200
        assert oa.run(CONFIG).status == "PASS"

    def test_vram_threshold_from_config(self, machine):
        machine["vram"] = 1200
        cfg = {"checks": {"ollama_activity": {"vram_idle_threshold_mib": 2000}}}
        assert oa.run(cfg).status == "PASS"

    def test_recent_inference_fails(self, machine):
        log = machine["tmp"] / "server.log"
        log.write_text(gin(5))
        machine["server_log"] = log
        r = oa.run(CONFIG)
        assert r.status == "FAIL" and "inference POST" in r.message

    def test_old_inference_ignored(self, machine):
        log = machine["tmp"] / "server.log"
        log.write_text(gin(120))
        machine["server_log"] = log
        assert oa.run(CONFIG).status == "PASS"

    def test_lookback_from_config(self, machine):
        log = machine["tmp"] / "server.log"
        log.write_text(gin(120))
        machine["server_log"] = log
        cfg = {"checks": {"ollama_activity": {"lookback_minutes": 240}}}
        assert oa.run(cfg).status == "FAIL"

    def test_old_vulnerable_version_fails(self, machine):
        machine["version"] = "0.16.3"
        r = oa.run(CONFIG)
        assert r.status == "FAIL" and any("CVE-2026-7482" in d for d in r.details)

    def test_fixed_version_passes(self, machine):
        machine["version"] = "0.17.1"
        assert oa.run(CONFIG).status == "PASS"

    def test_unknown_version_does_not_fail(self, machine):
        machine["version"] = None
        assert oa.run(CONFIG).status == "PASS"

    def test_two_minors_behind_warns(self, machine):
        app = machine["tmp"] / "app.log"
        app.write_text("New update available at https://github.com/ollama/ollama/releases/download/v0.43.0/OllamaSetup.exe\n")
        machine["app_log"] = app
        r = oa.run(CONFIG)
        assert r.status == "WARN" and any("minor version" in d for d in r.details)

    def test_one_minor_behind_is_fine(self, machine):
        app = machine["tmp"] / "app.log"
        app.write_text("New update available at https://github.com/ollama/ollama/releases/download/v0.41.0/OllamaSetup.exe\n")
        machine["app_log"] = app
        assert oa.run(CONFIG).status == "PASS"


class TestLogParsing:
    def test_counts_only_recent_posts_to_inference_endpoints(self, tmp_path):
        log = tmp_path / "server.log"
        log.write_text(gin(3) + gin(4, path="/api/chat") + gin(5, path="/api/embeddings")
                       + gin(6, method="GET") + gin(7, path="/api/tags") + gin(90))
        assert len(oa._parse_recent_inference(log, 30)) == 3

    def test_hit_text_has_status_and_path(self, tmp_path):
        log = tmp_path / "server.log"
        log.write_text(gin(2, status=500))
        hit = oa._parse_recent_inference(log, 30)[0]
        assert "HTTP 500" in hit and "POST /api/generate" in hit

    def test_missing_and_garbage_logs(self, tmp_path):
        assert oa._parse_recent_inference(tmp_path / "nope.log", 30) == []
        junk = tmp_path / "junk.log"
        junk.write_text("not a log line\n\x00\x01\n[GIN] bad\n")
        assert oa._parse_recent_inference(junk, 30) == []

    def test_available_update_takes_latest_line(self, tmp_path):
        app = tmp_path / "app.log"
        app.write_text(
            "New update available at https://x/releases/download/v0.30.0/OllamaSetup.exe\n"
            "other line\n"
            "New update available at https://x/releases/download/v0.31.2/OllamaSetup.exe\n")
        assert oa._parse_available_update(app) == "v0.31.2"

    def test_available_update_none_cases(self, tmp_path):
        assert oa._parse_available_update(None) is None
        assert oa._parse_available_update(tmp_path / "nope.log") is None
        plain = tmp_path / "app.log"
        plain.write_text("nothing here\n")
        assert oa._parse_available_update(plain) is None


class TestLogDiscovery:
    def test_prefers_active_server_log(self, monkeypatch, tmp_path):
        d = tmp_path / "Ollama"
        d.mkdir()
        (d / "server.log").write_text("x")
        (d / "server-1.log").write_text("old")
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert oa._find_server_log().name == "server.log"

    def test_falls_back_to_newest_rotated_log(self, monkeypatch, tmp_path):
        import os
        d = tmp_path / "Ollama"
        d.mkdir()
        (d / "server.log").write_text("")
        older, newer = d / "server-2.log", d / "server-1.log"
        older.write_text("a")
        newer.write_text("b")
        os.utime(older, (1, 1))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert oa._find_server_log().name == "server-1.log"

    def test_no_directory(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "none"))
        assert oa._find_server_log() is None and oa._find_app_log() is None
