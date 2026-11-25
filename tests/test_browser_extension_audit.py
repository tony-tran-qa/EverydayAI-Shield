"""
Tests for checks/check_browser_extension_audit.py - permission tiers, whitelist,
known-risky names and localized-name resolution, using a fake Chrome profile on disk.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_browser_extension_audit", ROOT / "checks" / "check_browser_extension_audit.py")
be = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(be)


@pytest.fixture
def chrome(monkeypatch, tmp_path):
    """Fake %LOCALAPPDATA% with an empty Chrome Default profile; returns an add() helper."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    ext_root = tmp_path / "Google" / "Chrome" / "User Data" / "Default" / "Extensions"
    ext_root.mkdir(parents=True)
    state = {"n": 0}

    def add(name="Some Ext", permissions=(), host_permissions=(), version="1.0.0", locales=None, ext_id=None):
        state["n"] += 1
        ext_id = ext_id or f"ext{state['n']:02d}" + "a" * 28
        vdir = ext_root / ext_id / version
        vdir.mkdir(parents=True)
        (vdir / "manifest.json").write_text(json.dumps({
            "name": name, "version": version,
            "permissions": list(permissions), "host_permissions": list(host_permissions)}))
        for loc, messages in (locales or {}).items():
            (vdir / "_locales" / loc).mkdir(parents=True)
            (vdir / "_locales" / loc / "messages.json").write_text(json.dumps(messages))
        return vdir

    add.root = ext_root
    return add


def cfg(whitelist=()):
    return {"checks": {"browser_extension_audit": {"enabled": True, "severity": "MEDIUM",
                                                    "whitelist": list(whitelist)}}}


class TestRun:
    def test_no_browser_dirs_passes(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "empty"))
        assert be.run(cfg()).status == "PASS"

    def test_harmless_extension_passes(self, chrome):
        chrome("Dark Reader", permissions=["storage", "tabs"])
        r = be.run(cfg())
        assert r.status == "PASS" and "1 scanned" in r.message

    @pytest.mark.parametrize("perm", ["debugger", "nativeMessaging", "clipboardRead", "proxy", "management"])
    def test_high_risk_permission_fails(self, chrome, perm):
        chrome("Shady Tool", permissions=[perm])
        r = be.run(cfg())
        assert r.status == "FAIL" and any("Shady Tool" in d for d in r.details)

    def test_three_elevated_permissions_fail(self, chrome):
        chrome("Greedy", permissions=["cookies", "history", "webRequestBlocking"])
        assert be.run(cfg()).status == "FAIL"

    def test_one_or_two_elevated_permissions_warn(self, chrome):
        chrome("Mild", permissions=["cookies", "history"])
        assert be.run(cfg()).status == "WARN"

    def test_all_urls_host_permission_counts_as_elevated(self, chrome):
        chrome("Everywhere", permissions=["storage"], host_permissions=["https://*/*"])
        assert be.run(cfg()).status == "WARN"

    def test_info_permissions_alone_do_not_flag(self, chrome):
        chrome("Bookmarker", permissions=["tabs", "bookmarks"])
        assert be.run(cfg()).status == "PASS"

    @pytest.mark.parametrize("name", ["Hola VPN", "Betternet Unlimited", "Touch VPN", "Browsec VPN"])
    def test_known_risky_names_fail(self, chrome, name):
        chrome(name, permissions=["storage"])
        assert be.run(cfg()).status == "FAIL"

    def test_whitelisted_extension_skipped_case_insensitively(self, chrome):
        chrome("Claude", permissions=["debugger", "nativeMessaging"])
        r = be.run(cfg(whitelist=["claude"]))
        assert r.status == "PASS" and any("whitelisted" in d for d in r.details)

    def test_whitelist_ignores_trademark_symbols_and_spacing(self, chrome):
        chrome("McAfee®  WebAdvisor", permissions=["nativeMessaging"])
        assert be.run(cfg(whitelist=["McAfee WebAdvisor"])).status == "PASS"

    def test_normalize_name(self):
        assert be.normalize_name("McAfee® WebAdvisor") == be.normalize_name("mcafee webadvisor")
        assert be.normalize_name("Foo™   Bar") == "foo bar"
        assert be.normalize_name(None) == ""
        assert be.normalize_name("Claude") != be.normalize_name("Claude Evil Clone")

    def test_whitelist_is_exact_not_substring(self, chrome):
        chrome("Claude Evil Clone", permissions=["debugger"])
        assert be.run(cfg(whitelist=["Claude"])).status == "FAIL"

    def test_fail_beats_warn(self, chrome):
        chrome("Mild", permissions=["cookies"])
        chrome("Shady", permissions=["debugger"])
        assert be.run(cfg()).status == "FAIL"

    def test_corrupt_manifest_is_skipped(self, chrome):
        vdir = chrome("Good", permissions=["storage"])
        bad = chrome.root / ("bad" + "b" * 29) / "1.0"
        bad.mkdir(parents=True)
        (bad / "manifest.json").write_text("{not json")
        assert be.run(cfg()).status == "PASS"

    def test_edge_and_brave_profiles_scanned_too(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        for base in (("Microsoft", "Edge"), ("BraveSoftware", "Brave-Browser")):
            v = tmp_path.joinpath(*base, "User Data", "Profile 1", "Extensions", "x" * 32, "1.0")
            v.mkdir(parents=True)
            (v / "manifest.json").write_text(json.dumps({"name": "Probe", "permissions": ["proxy"]}))
        r = be.run(cfg())
        assert r.status == "FAIL" and len([d for d in r.details if d.startswith("Scanning")]) == 2


class TestNameResolution:
    def test_localized_name_resolved(self, chrome):
        chrome("__MSG_appName__", locales={"en": {"appName": {"message": "Pretty Name"}}})
        info = be.audit_extension(next(chrome.root.iterdir()), "Chrome", "Default")
        assert info["name"] == "Pretty Name"

    def test_locale_fallback_en_us(self, chrome):
        chrome("__MSG_extName__", locales={"en_US": {"extName": {"message": "US Name"}}})
        info = be.audit_extension(next(chrome.root.iterdir()), "Chrome", "Default")
        assert info["name"] == "US Name"

    def test_unresolvable_name_uses_id_prefix(self, chrome):
        chrome("__MSG_missing__", ext_id="abcdefgh" + "z" * 24)
        info = be.audit_extension(next(chrome.root.iterdir()), "Chrome", "Default")
        assert info["name"] == "[abcdefgh]"

    def test_latest_version_directory_used(self, chrome):
        d = chrome("Old", ext_id="same" + "q" * 28, version="1.0.0")
        new = d.parent / "2.0.0"
        new.mkdir()
        (new / "manifest.json").write_text(json.dumps({"name": "New", "version": "2.0.0", "permissions": []}))
        info = be.audit_extension(d.parent, "Chrome", "Default")
        assert info["name"] == "New" and info["version"] == "2.0.0"

    def test_missing_manifest_returns_none(self, tmp_path):
        (tmp_path / "1.0").mkdir()
        assert be.audit_extension(tmp_path, "Chrome", "Default") is None

    def test_no_version_dirs_returns_none(self, tmp_path):
        assert be.audit_extension(tmp_path, "Chrome", "Default") is None
