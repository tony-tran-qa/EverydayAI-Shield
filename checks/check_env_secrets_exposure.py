"""
Check: env_secrets_exposure
Scans for AI API keys and secrets exposed in:
- System/user environment variables
- Common .env files
- PowerShell/CMD history
- Windows Credential Manager (partial)

Does NOT log the actual secret values — only reports presence and location.
"""

import os
import re
import subprocess
from pathlib import Path
from engine import CheckResult


def mask(value: str) -> str:
    """Show only first 4 and last 4 chars of a secret."""
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]


# Value formats of credentials that supply-chain malware and prompt-injected agents go after
# (Shai-Hulud / SANDWORM_MODE harvest npm, GitHub, cloud and AI-provider tokens).
TOKEN_PATTERNS = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("GitHub token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{50,}")),
    ("npm token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
]
NPMRC_TOKEN = re.compile(r"^\s*(?://[^\s=]+:)?_authToken\s*=\s*(\S+)", re.MULTILINE)
GIT_CRED_URL = re.compile(r"https?://[^:/\s]+:([^@\s]+)@")


# Directories never worth walking for .env files: caches, dependency trees, app data and temp.
SKIP_DIRS = {"node_modules", ".git", "appdata", "venv", ".venv", "site-packages",
             "__pycache__", "$recycle.bin", ".cache", ".npm", ".nuget"}
MAX_ENV_FILES = 50


def iter_env_files(root: Path, limit: int = MAX_ENV_FILES):
    """Yield .env files under root, pruning SKIP_DIRS (os.walk, so pruning avoids the walk entirely)."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        if ".env" in filenames:
            yield Path(dirpath) / ".env"
            count += 1
            if count >= limit:
                return


def unique_roots(roots) -> list:
    """Drop missing, duplicate and nested roots so each file is scanned once."""
    resolved = []
    for r in roots:
        try:
            if r.exists():
                resolved.append(r.resolve())
        except OSError:
            continue
    resolved = sorted(set(resolved), key=lambda p: len(p.parts))
    kept = []
    for r in resolved:
        if not any(k == r or k in r.parents for k in kept):
            kept.append(r)
    return kept


def _environ():
    """Process environment (indirection so tests can supply a fake one)."""
    return os.environ


def find_secret_tokens(text: str) -> list:
    """Return [(kind, masked_value)] for credential-format strings in text. Never returns raw secrets."""
    found = []
    for kind, pat in TOKEN_PATTERNS:
        for m in pat.finditer(text or ""):
            found.append((kind, mask(m.group(0))))
    return found


def find_plaintext_credentials(npmrc_text: str = "", git_credentials_text: str = "") -> list:
    """Plaintext npm auth tokens and git credential URLs. Env-var references (${NPM_TOKEN}) are fine."""
    out = []
    for m in NPMRC_TOKEN.finditer(npmrc_text or ""):
        val = m.group(1).strip("'\"")
        if val and not val.startswith("${"):
            out.append((".npmrc", f"plaintext npm _authToken {mask(val)}"))
    for m in GIT_CRED_URL.finditer(git_credentials_text or ""):
        out.append((".git-credentials", f"stored git password {mask(m.group(1))}"))
    return out


def run(config: dict) -> CheckResult:
    check_id = "env_secrets_exposure"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "CRITICAL")
    patterns = config.get("sensitive_env_patterns", [
        "API_KEY", "SECRET", "TOKEN", "PASSWORD",
        "ANTHROPIC", "OPENAI", "GEMINI", "COHERE"
    ])
    details = []
    issues = []
    warnings = []

    # 1. Scan current process environment variables
    exposed_env = []
    for key, val in _environ().items():
        for pat in patterns:
            if pat.upper() in key.upper():
                exposed_env.append((key, mask(val)))
                break

    if exposed_env:
        for k, v in exposed_env:
            details.append(f"ENV: {k} = {v}")
            # Warn if it's a broad system-level env (not just session)
            warnings.append(f"API credential in environment: {k}")

    # 2. Scan .env files in common locations
    scan_dirs = [
        Path.home(),
        Path.home() / "Documents",
        Path.home() / "Projects",
        Path.home() / "Desktop",
        Path(os.environ.get("USERPROFILE", "C:\\Users\\Default")),
    ]
    env_files_found = []
    secret_pattern = re.compile(
        r'(' + '|'.join(re.escape(p) for p in patterns) + r')\s*=\s*(\S+)',
        re.IGNORECASE
    )

    for scan_dir in unique_roots(scan_dirs):
        for env_file in iter_env_files(scan_dir):
            try:
                content = env_file.read_text(encoding="utf-8", errors="ignore")
                for kind, masked in find_secret_tokens(content):
                    issues.append(f"{kind} ({masked}) in {env_file}")
                matches = secret_pattern.findall(content)
                if matches:
                    env_files_found.append(str(env_file))
                    for key, val in matches:
                        issues.append(f".env file contains secret: {key} in {env_file}")
                        details.append(f"  {key} = {mask(val)} (in {env_file.name})")
            except Exception:
                pass
            if len(env_files_found) > 20:  # safety cap
                break

    # 3. Check PowerShell history for API key-like strings
    ps_history = Path(os.environ.get("APPDATA", "")) / \
        "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"

    if ps_history.exists():
        try:
            lines = ps_history.read_text(encoding="utf-8", errors="ignore").splitlines()
            key_like = re.compile(r'(sk-[a-zA-Z0-9\-_]{20,}|[A-Za-z0-9]{32,})')
            api_key_lines = []
            for i, line in enumerate(lines[-200:], 1):  # last 200 lines only
                for pat in patterns:
                    if pat.upper() in line.upper() and "=" in line:
                        api_key_lines.append(f"Line ~{len(lines)-200+i}: {line[:60]}...")
                        break
            token_hits = [t for line in lines[-200:] for t in find_secret_tokens(line)]
            if token_hits:
                issues.append(f"Credential-format token(s) typed in PowerShell history: "
                              + ", ".join(sorted({k for k, _ in token_hits})))
            if api_key_lines:
                issues.append(f"API key patterns found in PowerShell history ({len(api_key_lines)} line(s))")
                details.extend(api_key_lines[:5])  # show max 5
        except Exception as e:
            details.append(f"Could not read PS history: {e}")
    else:
        details.append("PowerShell history not found (or PSReadLine not installed)")

    # 3b. Plaintext package-manager / git credentials (first thing npm worms harvest)
    def _read(p: Path) -> str:
        try:
            return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""
        except Exception:
            return ""

    for where, what in find_plaintext_credentials(
            _read(Path.home() / ".npmrc"), _read(Path.home() / ".git-credentials")):
        warnings.append(f"{where}: {what}")
        details.append(f"  {where}: {what}")

    # 4. Check Windows Registry for accidentally stored keys
    reg_paths = [
        r"HKCU\Environment",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    ]
    for reg_path in reg_paths:
        try:
            result = subprocess.run(
                ["reg", "query", reg_path],
                capture_output=True, text=True, timeout=5
            )
            for pat in patterns:
                if pat.upper() in result.stdout.upper():
                    # Find the actual line
                    for line in result.stdout.splitlines():
                        if pat.upper() in line.upper():
                            issues.append(f"API credential in Windows Registry: {reg_path} → {line.strip()[:60]}")
        except Exception:
            pass

    # Aggregate
    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(issues)} secret exposure(s) detected",
            details=details + [f"⚠ {i}" for i in issues],
            remediation=(
                "1. Move secrets from .env files to Windows Credential Manager or a vault\n"
                "2. Clear PowerShell history: Remove-Item (Get-PSReadLineOption).HistorySavePath\n"
                "3. Remove secrets from Windows Registry environment variables\n"
                "4. Use per-project .env with .gitignore — never commit secrets"
            )
        )

    if warnings:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"{len(warnings)} credential exposure warning(s) — session env vars, plaintext .npmrc/.git-credentials",
            details=details + [f"⚡ {w}" for w in warnings],
            remediation="Consider using a secrets manager instead of environment variables for AI API keys"
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="No exposed secrets detected in common locations",
        details=details or ["No sensitive env vars, .env files, or PS history entries found"]
    )
