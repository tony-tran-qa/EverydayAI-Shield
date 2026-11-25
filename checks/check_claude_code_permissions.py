"""
Check: claude_code_permissions
Audits Claude Code configuration for over-permissive or attacker-controlled settings.

Reads the CURRENT settings schema (permissions.allow / defaultMode / additionalDirectories,
hooks, env, enableAllProjectMcpServers, apiKeyHelper) plus the legacy keys older
versions used. Scopes audited:
  - managed   %ProgramData%\\ClaudeCode\\managed-settings.json
  - user      ~/.claude/settings.json, ~/.claude/settings.local.json (+ legacy paths)
  - project   <project>/.claude/settings.json and settings.local.json for every project
              Claude Code has opened (listed in ~/.claude.json "projects")

Risks:
- defaultMode bypassPermissions (skips all permission prompts)
- unrestricted Bash allow rules
- project-level hooks / apiKeyHelper (run commands when a repo is opened)
- project-level enableAllProjectMcpServers (auto-approves MCP servers from a repo)
- env.ANTHROPIC_BASE_URL pointing away from Anthropic (API key redirection)
- additionalDirectories covering a drive root or the home folder
- Claude Code older than a known-vulnerable release
- running as Administrator, dangerous commands in CLAUDE.md

References: Claude Code settings/permissions docs; GitHub advisories for
@anthropic-ai/claude-code (CVE-2026-21852 project-config API key exfiltration,
CVE-2025-59536 hooks / MCP consent, CVE-2026-55607 fixed in 2.1.163).
"""

import json
import os
import re
import shutil
import subprocess
import ctypes
import time
from pathlib import Path
from urllib.parse import urlparse
from engine import CheckResult


def expand(p: str) -> Path:
    return Path(os.path.expandvars(p))


# Oldest release considered free of the advisories reviewed (CVE-2026-55607 fixed in 2.1.163)
MIN_SAFE_VERSION = (2, 1, 163)
DEFAULT_MAX_PATCHES_BEHIND = 20
LATEST_CACHE_SECONDS = 6 * 3600
_latest_cache = {"value": None, "at": 0.0}

ALLOWED_BASE_URL_HOSTS = ("anthropic.com", "localhost", "127.0.0.1", "::1")

USER_SETTINGS_PATHS = [
    "%USERPROFILE%\\.claude\\settings.json",
    "%USERPROFILE%\\.claude\\settings.local.json",
    # legacy locations older docs/tools used
    "%USERPROFILE%\\.claude\\config.json",
    "%APPDATA%\\claude-code\\settings.json",
    "%USERPROFILE%\\.config\\claude-code\\settings.json",
]
MANAGED_SETTINGS_PATHS = [
    "%ProgramData%\\ClaudeCode\\managed-settings.json",
]
CLAUDE_STATE_FILE = "%USERPROFILE%\\.claude.json"
MAX_PROJECTS = 200

UNRESTRICTED_BASH = {"bash", "bash(*)", "bash(:*)", "bash(**)", "*"}
RISKY_BASH_PREFIXES = (
    "bash(curl", "bash(wget", "bash(powershell", "bash(pwsh", "bash(cmd",
    "bash(rm", "bash(del", "bash(sudo", "bash(iwr", "bash(invoke-webrequest",
    "bash(python", "bash(node", "bash(npx", "bash(git push",
)
RISKY_HOOK_PATTERNS = [
    r"curl\s", r"wget\s", r"invoke-webrequest", r"\biwr\b", r"powershell", r"pwsh",
    r"base64", r"https?://", r"\bnc\s", r"certutil", r"bitsadmin", r"mshta",
]
DANGEROUS_CLAUDE_MD = ["rm -rf", "del /f", "format c:", "net user", "reg delete"]
ROOT_DIRS = {"c:", "d:", "/", "~"}


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# -- Version helpers -----------------------------------------------------------

def parse_version(text: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def installed_version():
    try:
        r = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=10)
        return parse_version(r.stdout)
    except Exception:
        return None


def latest_version():
    """Latest published @anthropic-ai/claude-code, cached (scans run every minute)."""
    now = time.time()
    if _latest_cache["value"] is not None and now - _latest_cache["at"] < LATEST_CACHE_SECONDS:
        return _latest_cache["value"]
    try:
        # npm is npm.cmd on Windows; a bare "npm" is not found without a shell
        npm = shutil.which("npm") or "npm"
        r = subprocess.run([npm, "view", "@anthropic-ai/claude-code", "version"],
                           capture_output=True, text=True, timeout=20)
        v = parse_version(r.stdout)
    except Exception:
        v = None
    if v:
        _latest_cache.update(value=v, at=now)
    return v


def version_findings(installed, latest, max_behind=DEFAULT_MAX_PATCHES_BEHIND):
    """Return (issues, warnings, details) for a version comparison. Pure function."""
    issues, warnings, details = [], [], []
    if not installed:
        return issues, warnings, details
    vs = ".".join(map(str, installed))
    details.append(f"Claude Code version: {vs}")
    if installed < MIN_SAFE_VERSION:
        issues.append(
            f"Claude Code {vs} is older than {'.'.join(map(str, MIN_SAFE_VERSION))}, "
            "which contains known sandbox-escape and permission-bypass vulnerabilities"
        )
    if latest and installed < latest:
        behind_minor = installed[:2] != latest[:2]
        patches = latest[2] - installed[2]
        if behind_minor or patches >= max_behind:
            warnings.append(
                f"Claude Code {vs} is behind the latest {'.'.join(map(str, latest))}"
                " - update (claude update or npm i -g @anthropic-ai/claude-code)"
            )
        else:
            details.append(f"Latest published: {'.'.join(map(str, latest))}")
    return issues, warnings, details


# -- Settings analysis (pure) --------------------------------------------------

def _collect_commands(node) -> list:
    """Collect every hook 'command' string from nested hook config."""
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "command" and isinstance(v, str):
                found.append(v)
            else:
                found.extend(_collect_commands(v))
    elif isinstance(node, list):
        for item in node:
            found.extend(_collect_commands(item))
    elif isinstance(node, str):
        found.append(node)
    return found


def _host_allowed(url: str, extra_hosts=()) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    for ok in tuple(ALLOWED_BASE_URL_HOSTS) + tuple(h.lower() for h in extra_hosts):
        if host == ok or host.endswith("." + ok):
            return True
    return False


def _is_broad_dir(d: str) -> bool:
    norm = d.strip().lower().replace("/", "\\").rstrip("\\")
    if norm in ROOT_DIRS or norm == "":
        return True
    return norm == str(Path.home()).lower().replace("/", "\\").rstrip("\\")


def analyze_settings(cfg, label: str, scope: str, extra_hosts=()):
    """Inspect one settings dict. Returns (issues, warnings). scope: managed|user|project."""
    issues, warnings = [], []
    if not isinstance(cfg, dict):
        return issues, warnings
    project = scope == "project"
    perms = cfg.get("permissions") if isinstance(cfg.get("permissions"), dict) else {}

    # Permission mode
    mode = perms.get("defaultMode") or cfg.get("defaultMode")
    if mode == "bypassPermissions":
        issues.append(f"defaultMode=bypassPermissions in {label} - Claude acts with no permission prompts")
    if (cfg.get("autoApprove") or cfg.get("auto_approve") or cfg.get("dangerouslySkipPermissions")
            or perms.get("dangerouslySkipPermissions")):
        warnings.append(f"Legacy auto-approve key in {label} (ignored by current Claude Code, but shows intent)")

    # Allow rules (current + legacy allowedTools)
    allow = list(perms.get("allow") or []) + list(cfg.get("allowedTools") or [])
    risky_rules = []
    for rule in allow:
        if not isinstance(rule, str):
            continue
        low = rule.strip().lower()
        if low in UNRESTRICTED_BASH:
            warnings.append(f"Unrestricted shell allow rule '{rule}' in {label} - Claude can run any command without asking")
        elif low.startswith(RISKY_BASH_PREFIXES) and "*" in low:
            # Only wildcard rules are broad. Exact one-off commands (saved by "always allow") are not.
            risky_rules.append(rule)
    if risky_rules:
        example = risky_rules[0] if len(risky_rules[0]) <= 60 else risky_rules[0][:57] + "..."
        warnings.append(
            f"{len(risky_rules)} wildcard allow rule(s) for shell/interpreters in {label} "
            f"(e.g. '{example}') - each lets Claude run arbitrary variations without asking"
        )

    # Directory scope
    dirs = list(perms.get("additionalDirectories") or []) + list(cfg.get("additionalDirectories") or []) \
        + list(cfg.get("trustedDirectories") or [])
    trust = cfg.get("trust")
    if isinstance(trust, dict):
        dirs += list(trust.get("directories") or [])
    for d in dirs:
        if isinstance(d, str) and _is_broad_dir(d):
            issues.append(f"Directory '{d}' in {label} grants root/home-wide file access")

    # Hooks
    hook_cmds = _collect_commands(cfg.get("hooks")) if cfg.get("hooks") else []
    if hook_cmds:
        risky = [c for c in hook_cmds if any(re.search(p, c, re.IGNORECASE) for p in RISKY_HOOK_PATTERNS)]
        if risky and project:
            issues.append(f"Project hook in {label} runs network/shell commands automatically: {risky[0][:80]}")
        elif risky:
            warnings.append(f"Hook in {label} uses network/shell commands: {risky[0][:80]}")
        elif project:
            warnings.append(f"Project-level hooks in {label} run commands when the repo is opened - review them")

    # apiKeyHelper runs a command to fetch credentials
    if cfg.get("apiKeyHelper") and project:
        issues.append(f"apiKeyHelper set in project settings {label} - a repo can run a command to supply credentials")

    # MCP auto-approval
    if cfg.get("enableAllProjectMcpServers") is True:
        if project:
            issues.append(f"enableAllProjectMcpServers=true in {label} - MCP servers from this repo start without consent")
        else:
            warnings.append(f"enableAllProjectMcpServers=true in {label} - repo MCP servers auto-approved")

    # API redirection
    env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
    base = env.get("ANTHROPIC_BASE_URL")
    if isinstance(base, str) and base and not _host_allowed(base, extra_hosts):
        msg = f"env.ANTHROPIC_BASE_URL={base} in {label} - API traffic and key go to a non-Anthropic host"
        (issues if project else warnings).append(msg)

    return issues, warnings


def find_project_settings(state_path: Path, limit: int = MAX_PROJECTS) -> list:
    """Project settings files for every project Claude Code has opened (from ~/.claude.json)."""
    out = []
    try:
        data = json.loads(Path(state_path).read_text(encoding="utf-8"))
    except Exception:
        return out
    projects = data.get("projects") if isinstance(data, dict) else None
    if not isinstance(projects, dict):
        return out
    seen = set()
    for proj in list(projects.keys())[:limit]:
        for name in ("settings.json", "settings.local.json"):
            f = Path(proj) / ".claude" / name
            key = os.path.normcase(os.path.normpath(str(f)))
            if key in seen:
                continue
            if f.exists():
                seen.add(key)
                out.append(f)
    return out


def _load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run(config: dict) -> CheckResult:
    check_id = "claude_code_permissions"
    check_cfg = config.get("checks", {}).get(check_id, {})
    severity = check_cfg.get("severity", "HIGH")
    extra_hosts = check_cfg.get("allowed_base_url_hosts", [])
    max_behind = check_cfg.get("max_patches_behind", DEFAULT_MAX_PATCHES_BEHIND)
    details, issues, warnings = [], [], []

    # 1. Is Claude Code installed?
    claude_found = False
    exe = shutil.which("claude")
    if exe:
        claude_found = True
        details.append(f"Claude Code CLI found: {exe}")
    else:
        try:
            result = subprocess.run([shutil.which("npm") or "npm", "list", "-g", "--depth=0"],
                                    capture_output=True, text=True, timeout=10)
            if "@anthropic-ai/claude-code" in result.stdout:
                claude_found = True
                details.append("Claude Code found via npm global")
        except Exception:
            pass

    if not claude_found:
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="Claude Code CLI not detected on this machine", details=details
        )

    # 2. Version currency
    v_issues, v_warnings, v_details = version_findings(installed_version(), latest_version(), max_behind)
    issues += v_issues
    warnings += v_warnings
    details += v_details

    # 3. Settings files by scope
    targets = [(expand(p), "managed") for p in MANAGED_SETTINGS_PATHS]
    targets += [(expand(p), "user") for p in USER_SETTINGS_PATHS]
    targets += [(p, "project") for p in find_project_settings(expand(CLAUDE_STATE_FILE))]
    scanned = 0
    for path, scope in targets:
        if not path.exists():
            continue
        scanned += 1
        label = f"{scope}:{path}" if scope == "project" else f"{path.name}"
        try:
            cfg = _load_json(path)
        except json.JSONDecodeError as e:
            details.append(f"Could not parse {path}: {e}")
            continue
        except OSError as e:
            details.append(f"Could not read {path}: {e}")
            continue
        details.append(f"Config found ({scope}): {path}")
        i, w = analyze_settings(cfg, label, scope, extra_hosts)
        issues += i
        warnings += w
    if not scanned:
        details.append("No Claude Code settings files found - using defaults")

    # 4. Elevated session
    if is_admin():
        issues.append("Current session is running as Administrator - Claude Code can modify system files")

    # 5. CLAUDE.md with dangerous commands
    for root in [Path.home(), Path.home() / "Documents", Path.home() / "Projects"]:
        claude_md = root / "CLAUDE.md"
        if claude_md.exists():
            try:
                content = claude_md.read_text(encoding="utf-8", errors="ignore").lower()
                for pat in DANGEROUS_CLAUDE_MD:
                    if pat in content:
                        issues.append(f"Dangerous command pattern '{pat}' found in {claude_md}")
            except Exception:
                pass

    remediation = (
        "1. Remove defaultMode=bypassPermissions; set permissions.disableBypassPermissionsMode=\"disable\"\n"
        "2. Replace unrestricted Bash allow rules with specific commands, e.g. Bash(npm run test *)\n"
        "3. Review project .claude/settings*.json (hooks, apiKeyHelper, env, enableAllProjectMcpServers) in repos you did not write\n"
        "4. Remove ANTHROPIC_BASE_URL overrides you did not set yourself\n"
        "5. Update Claude Code and run it as a standard user, not Administrator"
    )
    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(issues)} high-risk Claude Code configuration(s) detected",
            details=details + [f"⚠ {i}" for i in issues] + [f"⚡ {w}" for w in warnings],
            remediation=remediation
        )
    if warnings:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"Claude Code has {len(warnings)} elevated-risk setting(s)",
            details=details + [f"⚡ {w}" for w in warnings],
            remediation=remediation
        )
    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="Claude Code permissions look reasonable", details=details
    )
