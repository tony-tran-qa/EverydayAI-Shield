"""
Tests for checks/check_env_secrets_exposure.py - credential-format detection,
plaintext npm/git credentials, masking, and the run() aggregate.
Fake token strings are assembled at runtime so no secret-looking literal is committed.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_env_secrets_exposure", ROOT / "checks" / "check_env_secrets_exposure.py")
es = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(es)

CONFIG = {"checks": {"env_secrets_exposure": {"enabled": True, "severity": "CRITICAL"}}}

A36 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"          # 36 alnum
ANTHROPIC = "sk-" + "ant-" + "api03-" + "x" * 30
OPENAI = "sk-" + "proj-" + "y" * 40
GH = "gh" + "p_" + A36
GH_PAT = "github" + "_pat_" + "z" * 60
NPM = "np" + "m_" + A36
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
GOOGLE = "AI" + "za" + "S" * 35
SLACK = "xo" + "xb-" + "1234567890-abcdef"


class TestMask:
    def test_short_values_fully_hidden(self):
        assert es.mask("abc") == "***"
        assert es.mask("12345678") == "***"

    def test_long_values_show_only_ends(self):
        m = es.mask("abcdefghijklmnop")
        assert m == "abcd...mnop" and "efghijkl" not in m


class TestTokenFormats:
    @pytest.mark.parametrize("token,kind", [
        (ANTHROPIC, "Anthropic API key"), (OPENAI, "OpenAI API key"), (GH, "GitHub token"),
        (GH_PAT, "GitHub fine-grained token"), (NPM, "npm token"), (AWS, "AWS access key id"),
        (GOOGLE, "Google API key"), (SLACK, "Slack token"),
    ])
    def test_detects_each_format(self, token, kind):
        kinds = [k for k, _ in es.find_secret_tokens(f"export KEY={token}")]
        assert kind in kinds

    def test_anthropic_key_not_double_counted_as_openai(self):
        kinds = [k for k, _ in es.find_secret_tokens(ANTHROPIC)]
        assert kinds == ["Anthropic API key"]

    def test_result_never_contains_raw_secret(self):
        for _, masked in es.find_secret_tokens(f"a {GH} b {ANTHROPIC}"):
            assert GH not in masked and ANTHROPIC not in masked
            assert "..." in masked

    @pytest.mark.parametrize("text", ["", None, "hello world", "sk-short", "ghp_tooshort", "AKIA123", "npm_abc"])
    def test_benign_text_has_no_hits(self, text):
        assert es.find_secret_tokens(text) == []

    def test_multiple_in_one_blob(self):
        assert len(es.find_secret_tokens(f"{GH}\n{NPM}\n{AWS}")) == 3


class TestPlaintextCredentials:
    def test_npmrc_plaintext_token_flagged(self):
        out = es.find_plaintext_credentials(npmrc_text=f"//registry.npmjs.org/:_authToken={NPM}\n")
        assert len(out) == 1 and out[0][0] == ".npmrc" and NPM not in out[0][1]

    def test_npmrc_env_reference_is_fine(self):
        assert es.find_plaintext_credentials(npmrc_text="//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n") == []

    def test_npmrc_without_token_is_fine(self):
        assert es.find_plaintext_credentials(npmrc_text="registry=https://registry.npmjs.org/\n") == []

    def test_git_credentials_password_flagged_and_masked(self):
        pw = "hunter2hunter2"
        out = es.find_plaintext_credentials(git_credentials_text=f"https://user:{pw}@github.com\n")
        assert len(out) == 1 and out[0][0] == ".git-credentials" and pw not in out[0][1]

    def test_empty_inputs(self):
        assert es.find_plaintext_credentials() == []
        assert es.find_plaintext_credentials(None, None) == []


class TestEnvFileDiscovery:
    def test_finds_nested_env_files(self, tmp_path):
        (tmp_path / "proj" / "sub").mkdir(parents=True)
        (tmp_path / ".env").write_text("A=1")
        (tmp_path / "proj" / "sub" / ".env").write_text("B=2")
        assert len(list(es.iter_env_files(tmp_path))) == 2

    @pytest.mark.parametrize("skipped", ["node_modules", ".git", "AppData", "venv", ".venv", "site-packages"])
    def test_skips_noise_directories(self, tmp_path, skipped):
        d = tmp_path / skipped / "deep"
        d.mkdir(parents=True)
        (d / ".env").write_text("A=1")
        assert list(es.iter_env_files(tmp_path)) == []

    def test_limit_respected(self, tmp_path):
        for i in range(5):
            (tmp_path / f"p{i}").mkdir()
            (tmp_path / f"p{i}" / ".env").write_text("A=1")
        assert len(list(es.iter_env_files(tmp_path, limit=3))) == 3

    def test_ignores_similar_names(self, tmp_path):
        (tmp_path / ".env.example").write_text("A=1")
        (tmp_path / "env").write_text("A=1")
        assert list(es.iter_env_files(tmp_path)) == []

    def test_unique_roots_drops_missing_duplicate_and_nested(self, tmp_path):
        (tmp_path / "Documents").mkdir()
        roots = [tmp_path, tmp_path / "Documents", tmp_path, tmp_path / "missing"]
        assert es.unique_roots(roots) == [tmp_path.resolve()]


@pytest.fixture
def machine(monkeypatch, tmp_path):
    """Isolated fake machine: empty env, empty home, no registry, no history."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(es.Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setattr(es, "_environ", lambda: {})

    class R:
        stdout = ""

    monkeypatch.setattr(es.subprocess, "run", lambda *a, **k: R())
    return {"home": home, "tmp": tmp_path}


class TestRun:
    def test_clean_machine_passes(self, machine):
        assert es.run(CONFIG).status == "PASS"

    def test_env_var_with_secret_name_warns(self, machine, monkeypatch):
        monkeypatch.setattr(es, "_environ", lambda: {"ANTHROPIC_API_KEY": "sk-whatever-value-123456"})
        r = es.run(CONFIG)
        assert r.status == "WARN"
        assert not any("whatever-value" in d for d in r.details)

    def test_env_file_with_token_format_fails(self, machine):
        (machine["home"] / ".env").write_text(f"SOMETHING={GH}\n")
        r = es.run(CONFIG)
        assert r.status == "FAIL"
        assert any("GitHub token" in d for d in r.details)
        assert not any(GH in d for d in r.details)

    def test_env_file_with_named_secret_fails(self, machine):
        (machine["home"] / ".env").write_text("MY_API_KEY=abcdef123456\n")
        assert es.run(CONFIG).status == "FAIL"

    def test_plaintext_npmrc_warns(self, machine):
        (machine["home"] / ".npmrc").write_text(f"//registry.npmjs.org/:_authToken={NPM}\n")
        r = es.run(CONFIG)
        assert r.status == "WARN"
        assert not any(NPM in d for d in r.details)

    def test_powershell_history_token_fails(self, machine):
        hist = machine["tmp"] / "appdata" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
        hist.mkdir(parents=True)
        (hist / "ConsoleHost_history.txt").write_text(f"git clone https://x:{GH}@github.com/a/b\n")
        r = es.run(CONFIG)
        assert r.status == "FAIL"
        assert any("PowerShell history" in d for d in r.details)

    def test_registry_secret_fails(self, machine, monkeypatch):
        class R:
            stdout = "    MY_SECRET    REG_SZ    topsecretvalue\n"

        monkeypatch.setattr(es.subprocess, "run", lambda *a, **k: R())
        assert es.run(CONFIG).status == "FAIL"


class TestUnresolvedTemplatePlaceholders:
    """${...} values are unfilled templates (e.g. Claude Desktop extension settings), not secrets."""

    @pytest.fixture(autouse=True)
    def _isolate(self, monkeypatch, tmp_path):
        monkeypatch.setattr(es.Path, "home", classmethod(lambda cls: tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        class R:
            returncode = 1
            stdout = ""
            stderr = ""
        monkeypatch.setattr(es.subprocess, "run", lambda *a, **k: R())

    def test_unresolved_placeholder_is_not_flagged(self, monkeypatch):
        monkeypatch.setattr(es, "_environ", lambda: {"API_KEY": "${user_config.api_key}"})
        r = es.run(CONFIG)
        assert r.status == "PASS"
        assert any("unresolved template" in d for d in r.details)

    def test_placeholder_detail_does_not_claim_exposure(self, monkeypatch):
        monkeypatch.setattr(es, "_environ", lambda: {"API_KEY": "${user_config.api_key}"})
        r = es.run(CONFIG)
        assert not any("API credential in environment" in d for d in r.details)

    def test_real_value_still_flagged(self, monkeypatch):
        monkeypatch.setattr(es, "_environ", lambda: {"API_KEY": "sk-real-looking-value-1234567890"})
        assert es.run(CONFIG).status == "WARN"

    def test_partial_template_with_real_text_still_flagged(self, monkeypatch):
        monkeypatch.setattr(es, "_environ", lambda: {"API_KEY": "prefix-${x}-realsecretvalue99"})
        assert es.run(CONFIG).status == "WARN"
