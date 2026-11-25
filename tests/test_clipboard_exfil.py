"""
Tests for checks/check_clipboard_exfil.py - sensitive-pattern detection and masking.
The clipboard is never read: get_clipboard_text is stubbed. Fake secrets are built at runtime.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_clipboard_exfil", ROOT / "checks" / "check_clipboard_exfil.py")
ce = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ce)

CONFIG = {"checks": {"clipboard_exfil": {"enabled": True, "severity": "MEDIUM"}}}

ANTHROPIC = "sk-" + "ant-" + "z" * 50
OPENAI = "sk-" + "p" * 48
GITHUB = "gh" + "p_" + "A" * 36
GITHUB_APP = "gh" + "s_" + "B" * 36
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
GOOGLE = "AI" + "za" + "C" * 35
SLACK = "xo" + "xb-" + "1234567890-abcdef"
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE..."
CARD = "4111" + "1111" + "1111" + "1111"


def run_with(monkeypatch, text):
    monkeypatch.setattr(ce, "get_clipboard_text", lambda: text)
    return ce.run(CONFIG)


class TestDetection:
    @pytest.mark.parametrize("secret,label", [
        (ANTHROPIC, "Anthropic API key"),
        (OPENAI, "OpenAI API key"),
        (GITHUB, "GitHub Personal Access Token"),
        (GITHUB_APP, "GitHub App Token"),
        (AWS, "AWS Access Key ID"),
        (GOOGLE, "Google API key"),
        (SLACK, "Slack token"),
        (PRIVATE_KEY, "Private key"),
        ("password = Sup3rSecret99", "Password in config format"),
        ("SSN 123-45-6789 on file", "SSN-pattern"),
        (CARD, "Credit card number"),
    ])
    def test_each_pattern_warns(self, monkeypatch, secret, label):
        r = run_with(monkeypatch, f"please look at {secret} thanks")
        assert r.status == "WARN"
        assert any(label in d for d in r.details), r.details

    def test_multiple_secrets_counted(self, monkeypatch):
        r = run_with(monkeypatch, f"{GITHUB}\n{AWS}\n{CARD}")
        assert r.status == "WARN" and "3 pattern(s)" in r.message

    def test_warn_not_fail(self, monkeypatch):
        # user-driven risk: never FAIL
        assert run_with(monkeypatch, ANTHROPIC).status == "WARN"


class TestBenign:
    @pytest.mark.parametrize("text", [
        "hello world",
        "meeting at 3pm, call 226-929-8890",
        "https://github.com/tony-tran-qa/EverydayAI-Shield",
        "def add(a, b): return a + b",
        "password",
        "sk-short",
        "12-34-5678",
    ])
    def test_plain_text_passes(self, monkeypatch, text):
        assert run_with(monkeypatch, text).status == "PASS"

    def test_empty_clipboard_passes(self, monkeypatch):
        r = run_with(monkeypatch, "")
        assert r.status == "PASS" and "empty" in r.message.lower()

    def test_unreadable_clipboard_passes(self, monkeypatch):
        r = run_with(monkeypatch, None)
        assert r.status == "PASS" and "Could not read" in r.message


class TestPrivacy:
    def test_secret_never_appears_in_output(self, monkeypatch):
        r = run_with(monkeypatch, f"token {GITHUB}")
        blob = "\n".join(r.details) + r.message + r.remediation
        assert GITHUB not in blob
        assert "..." in blob

    def test_content_length_reported_not_content(self, monkeypatch):
        r = run_with(monkeypatch, "just some notes")
        assert any("length" in d for d in r.details)
        assert not any("just some notes" in d for d in r.details)


class TestGetClipboard:
    def test_returns_stripped_stdout(self, monkeypatch):
        class R:
            stdout = "  copied text \n"

        monkeypatch.setattr(ce.subprocess, "run", lambda *a, **k: R())
        assert ce.get_clipboard_text() == "copied text"

    def test_returns_none_on_failure(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("no powershell")

        monkeypatch.setattr(ce.subprocess, "run", boom)
        assert ce.get_clipboard_text() is None
