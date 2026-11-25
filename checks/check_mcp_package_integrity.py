"""
Check: mcp_package_integrity
Supply chain attack detection for MCP servers.

Targets the axios-style RAT attack pattern (March 2026):
- Malicious npm packages installed as MCP servers
- Packages with post-install hooks that beacon home
- MCP config pointing to untrusted package sources
- Known suspicious package names
- Packages with shell execution in install scripts

Reference: Axios supply chain RAT attack against Claude MCP ecosystem (March 2026)
"""

import json
import os
import shutil
import subprocess
import re
from pathlib import Path
from engine import CheckResult

# Typosquats of AI tooling published by the SANDWORM_MODE npm campaign (Socket, Feb 2026).
# These are always checked, in addition to config.json "suspicious_npm_packages".
KNOWN_TYPOSQUATS = ["claud-code", "cloude-code"]
LAUNCHERS = ("npx", "uvx", "bunx", "pnpm dlx")


def parse_pkg_spec(spec: str):
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3'); 'name' -> ('name', None)."""
    spec = (spec or "").strip().strip("'\"")
    idx = spec.rfind("@")
    if idx > 0:
        return spec[:idx].lower(), spec[idx + 1:] or None
    return spec.lower(), None


def launched_package(cmd: str, args: list):
    """Package spec an npx/uvx-style MCP server fetches from a registry, or None."""
    base = os.path.basename(str(cmd)).lower()
    base = re.sub(r"\.(cmd|exe|bat)$", "", base)
    if base not in ("npx", "uvx", "bunx"):
        return None
    for a in args or []:
        if isinstance(a, str) and not a.startswith("-"):
            return a
    return None


def is_pinned(spec: str) -> bool:
    _, version = parse_pkg_spec(spec)
    return bool(version) and version.lower() not in ("latest", "next", "*")


def is_known_bad(spec: str, bad_names) -> str | None:
    """Exact package-name match (version stripped) against known-bad names."""
    name, _ = parse_pkg_spec(spec)
    for bad in bad_names:
        if name == bad.lower():
            return bad
    return None


# Expand Windows env vars in paths
def expand(p: str) -> Path:
    return Path(os.path.expandvars(p))


def get_mcp_configs(config: dict) -> list[dict]:
    """Load all MCP config files found on this machine."""
    mcp_data = []
    for path_template in config.get("mcp_paths", []):
        path = expand(path_template)
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    mcp_data.append({"path": str(path), "data": data})
            except Exception as e:
                mcp_data.append({"path": str(path), "error": str(e)})
    return mcp_data


def check_package_json(pkg_dir: Path) -> list[str]:
    """Inspect a package's package.json for red flags."""
    flags = []
    pkg_json = pkg_dir / "package.json"
    if not pkg_json.exists():
        return flags

    try:
        with open(pkg_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return [f"Could not parse {pkg_json}"]

    scripts = data.get("scripts", {})
    suspicious_script_patterns = [
        r"curl\s+", r"wget\s+", r"powershell", r"cmd\.exe",
        r"exec\(", r"eval\(", r"base64", r"net\s+user",
        r"schtasks", r"reg\s+add", r"certutil"
    ]

    for script_name, script_val in scripts.items():
        if script_name in ("postinstall", "preinstall", "install", "prepare"):
            for pattern in suspicious_script_patterns:
                if re.search(pattern, script_val, re.IGNORECASE):
                    flags.append(
                        f"SUSPICIOUS install hook in {pkg_dir.name}/{script_name}: "
                        f"contains '{pattern.strip()}'"
                    )

    return flags


def extract_mcp_packages(mcp_data: list[dict]) -> list[str]:
    """Extract npm package names/paths from MCP server configs."""
    packages = []
    for entry in mcp_data:
        data = entry.get("data", {})
        servers = data.get("mcpServers", {})
        for server_name, server_cfg in servers.items():
            cmd = server_cfg.get("command", "")
            args = server_cfg.get("args", [])
            # npx-style: npx -y some-package
            if "npx" in cmd or (args and "npx" in " ".join(args)):
                full = " ".join([cmd] + args)
                match = re.search(r'npx\s+(?:-y\s+)?(@?[\w\-/]+)', full)
                if match:
                    packages.append(match.group(1))
            # node path style
            for arg in args:
                if arg.endswith(".js") or arg.endswith("index.js"):
                    pkg_path = Path(arg).parent
                    packages.append(str(pkg_path))
    return packages


def run(config: dict) -> CheckResult:
    check_id = "mcp_package_integrity"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "CRITICAL")
    details = []
    issues = []
    suspicious_known = list(dict.fromkeys(config.get("suspicious_npm_packages", []) + KNOWN_TYPOSQUATS))
    unpinned = []

    # 1. Find MCP configs
    mcp_configs = get_mcp_configs(config)
    if not mcp_configs:
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="No MCP config files found on this machine",
            details=["Checked: " + ", ".join(config.get("mcp_paths", []))]
        )

    for entry in mcp_configs:
        if "error" in entry:
            details.append(f"Parse error in {entry['path']}: {entry['error']}")
            continue
        details.append(f"MCP config found: {entry['path']}")
        servers = entry["data"].get("mcpServers", {})
        for name, cfg in servers.items():
            cmd = str(cfg.get("command", ""))
            args = cfg.get("args", [])
            details.append(f"  Server: {name} → {cmd} {' '.join(args)}")

            # Check against known bad package list (exact package name, version stripped)
            tokens = [cmd] + [a for a in args if isinstance(a, str)]
            for tok in tokens:
                bad = is_known_bad(tok, suspicious_known)
                if bad:
                    issues.append(f"Known suspicious package '{bad}' in MCP server '{name}'")
                    break

            # Registry-fetched servers without a pinned version can change under you
            # (rug pull / compromised release). Pin with name@x.y.z.
            spec = launched_package(cmd, args)
            if spec and not is_pinned(spec):
                unpinned.append(name)
                details.append(f"  [WARN] {name} runs '{spec}' unpinned - any new release runs on next start")

    # 2. Check npm global packages for suspicious installs
    try:
        # npm is npm.cmd on Windows; a bare "npm" raises FileNotFoundError without a shell
        npm_exe = shutil.which("npm")
        if not npm_exe:
            raise FileNotFoundError("npm")
        result = subprocess.run(
            [npm_exe, "list", "-g", "--depth=0", "--json"],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout:
            npm_data = json.loads(result.stdout)
            global_pkgs = npm_data.get("dependencies", {})
            for pkg_name in global_pkgs:
                bad = is_known_bad(pkg_name, suspicious_known)
                if bad:
                    issues.append(f"Suspicious npm global package installed: {pkg_name}")
            details.append(f"Global npm packages checked: {len(global_pkgs)}")
    except FileNotFoundError:
        details.append("npm not found in PATH — skipping npm global check")
    except Exception as e:
        details.append(f"npm list error: {e}")

    # 3. Inspect package.json for post-install hooks in known MCP dirs
    mcp_pkg_dirs = [
        Path(os.environ.get("APPDATA", "")) / "npm" / "node_modules",
        Path(os.environ.get("USERPROFILE", "")) / ".npm-global" / "lib" / "node_modules",
    ]
    for pkg_root in mcp_pkg_dirs:
        if pkg_root.exists():
            for pkg_dir in pkg_root.iterdir():
                if pkg_dir.is_dir():
                    flags = check_package_json(pkg_dir)
                    issues.extend(flags)
                    if flags:
                        details.append(f"  Package with suspicious hooks: {pkg_dir.name}")

    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(issues)} supply chain risk(s) detected in MCP packages",
            details=details + [f"⚠ {i}" for i in issues],
            remediation=(
                "1. Remove flagged packages: npm uninstall -g <package>\n"
                "2. Pin MCP server versions in claude_desktop_config.json\n"
                "3. Prefer local paths over npx for production MCP servers\n"
                "4. Review MCP server source on GitHub before installing"
            )
        )

    if unpinned:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"{len(unpinned)} MCP server(s) fetch unpinned packages: {', '.join(unpinned)}",
            details=details,
            remediation="Pin each registry-fetched MCP server to an exact version, e.g. npx -y @scope/server@1.2.3"
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message=f"MCP package integrity OK ({len(mcp_configs)} config(s) scanned)",
        details=details
    )
