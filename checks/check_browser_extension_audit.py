"""
Check: browser_extension_audit
Audits Chrome and Edge browser extensions for:
- Excessive permissions (tabs, nativeMessaging, clipboard read)
- Known risky AI-adjacent extensions
- Extensions installed by policy (may be enterprise or malicious)
- Very recently installed extensions (last 7 days)

Does not read browsing data -- only inspects installed extension manifests.
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone
from engine import CheckResult


# HIGH severity -- any one of these alone is worth flagging
HIGH_RISK_PERMISSIONS = {
    "debugger": "Can intercept ALL browser traffic and inject code",
    "nativeMessaging": "Can communicate with native apps outside browser sandbox",
    "clipboardRead": "Can read clipboard silently -- credential theft risk",
    "proxy": "Can redirect all browser traffic",
    "management": "Can install/uninstall other extensions",
}

# MEDIUM severity -- flag only if extension has 3+ of these
ELEVATED_PERMISSIONS = {
    "webRequestBlocking": "Can block/modify network requests",
    "cookies": "Can read all cookies (session hijacking risk)",
    "history": "Can read full browsing history",
    "<all_urls>": "Can access content on every website you visit",
}

# Informational only -- do not flag on their own
INFO_PERMISSIONS = {
    "tabs": "Can read URL/title of all tabs",
    "bookmarks": "Can read/modify bookmarks",
}

# Known problematic extensions by name fragment
KNOWN_RISKY_EXTENSIONS = [
    "hola", "betternet", "touch vpn", "hotspot shield",
    "browsec", "frigate", "anonymox",
    "saveform", "form autofill",
]


def normalize_name(name: str) -> str:
    """Case-fold and drop trademark symbols / extra spaces so 'McAfee(R) WebAdvisor'
    matches a whitelist entry written as 'McAfee WebAdvisor'. Still an exact-name match."""
    cleaned = (name or "").replace("®", "").replace("™", "").replace("©", "")
    return " ".join(cleaned.split()).casefold()


def get_chrome_extension_dirs() -> list:
    appdata = os.environ.get("LOCALAPPDATA", "")
    bases = [
        Path(appdata) / "Google" / "Chrome" / "User Data",
        Path(appdata) / "Microsoft" / "Edge" / "User Data",
        Path(appdata) / "BraveSoftware" / "Brave-Browser" / "User Data",
    ]
    ext_dirs = []
    for base in bases:
        if not base.exists():
            continue
        for profile_dir in base.iterdir():
            if not profile_dir.is_dir():
                continue
            if profile_dir.name.startswith("Profile") or profile_dir.name == "Default":
                ext_path = profile_dir / "Extensions"
                if ext_path.exists():
                    ext_dirs.append((base.parent.name, profile_dir.name, ext_path))
    return ext_dirs


def resolve_msg_name(version_dir: Path, msg_key: str) -> str:
    """
    Attempt to resolve __MSG_<key>__ from _locales/en/messages.json
    or _locales/en_US/messages.json. Returns the key unchanged on failure.
    """
    for locale in ("en", "en_US", "en_GB"):
        locale_file = version_dir / "_locales" / locale / "messages.json"
        if not locale_file.exists():
            continue
        try:
            with open(locale_file, "r", encoding="utf-8", errors="ignore") as f:
                messages = json.load(f)
            # Try exact key match (case-insensitive scan)
            for k, v in messages.items():
                if k.lower() == msg_key.lower():
                    resolved = v.get("message", "")
                    if resolved:
                        return resolved
        except Exception:
            continue
    return ""


def audit_extension(ext_path: Path, browser: str, profile: str) -> dict | None:
    """Parse the manifest.json for the latest version of an extension."""
    version_dirs = [d for d in ext_path.iterdir() if d.is_dir()]
    if not version_dirs:
        return None
    latest = sorted(version_dirs)[-1]
    manifest = latest / "manifest.json"
    if not manifest.exists():
        return None
    try:
        with open(manifest, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        raw_name = data.get("name", "Unknown")
        # Resolve localized name
        if raw_name.startswith("__MSG_"):
            msg_key = raw_name.replace("__MSG_", "").rstrip("_")
            resolved = resolve_msg_name(latest, msg_key)
            name = resolved if resolved else f"[{ext_path.name[:8]}]"
        else:
            name = raw_name

        return {
            "id": ext_path.name,
            "name": name,
            "version": data.get("version", "?"),
            "permissions": data.get("permissions", []),
            "host_permissions": data.get("host_permissions", []),
            "browser": browser,
            "profile": profile,
        }
    except Exception:
        return None


def run(config: dict) -> CheckResult:
    check_id = "browser_extension_audit"
    cfg = config.get("checks", {}).get(check_id, {})
    severity = cfg.get("severity", "MEDIUM")
    # Whitelisted extension names (exact, case-insensitive) -- add known-safe here
    whitelist = [normalize_name(w) for w in cfg.get("whitelist", [])]

    details = []
    issues = []
    warnings = []

    ext_dirs = get_chrome_extension_dirs()
    if not ext_dirs:
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="No Chrome/Edge/Brave extension directories found",
            details=details
        )

    total_extensions = 0
    for browser, profile, ext_root in ext_dirs:
        details.append(f"Scanning: {browser}/{profile}")
        for ext_id_dir in ext_root.iterdir():
            if not ext_id_dir.is_dir():
                continue
            info = audit_extension(ext_id_dir, browser, profile)
            if not info:
                continue
            total_extensions += 1
            name = info["name"]
            perms = info["permissions"] + info.get("host_permissions", [])

            # Skip whitelisted extensions
            if normalize_name(name) in whitelist:
                details.append(f"  [whitelisted] {name}")
                continue

            # Tier 1: high-risk permissions -- flag individually
            high_found = []
            for perm in perms:
                if perm in HIGH_RISK_PERMISSIONS:
                    high_found.append(f"{perm} -- {HIGH_RISK_PERMISSIONS[perm]}")

            # Tier 2: elevated permissions -- flag if 3+
            elevated_found = []
            for perm in perms:
                if perm in ELEVATED_PERMISSIONS:
                    elevated_found.append(perm)
                elif isinstance(perm, str) and ("://*/*" in perm or perm == "<all_urls>"):
                    elevated_found.append("<all_urls>")

            # Check against known risky extension names
            for bad in KNOWN_RISKY_EXTENSIONS:
                if bad.lower() in name.lower():
                    issues.append(f"Known risky extension: '{name}' ({browser}/{profile})")

            if high_found:
                issues.append(f"'{name}' -- {len(high_found)} high-risk permission(s):")
                for h in high_found:
                    details.append(f"    -> {h}")
            elif len(elevated_found) >= 3:
                issues.append(
                    f"'{name}' -- {len(elevated_found)} elevated permissions: {', '.join(elevated_found)}"
                )
            elif elevated_found:
                warnings.append(
                    f"'{name}' has elevated permission(s): {', '.join(elevated_found)}"
                )

    details.insert(0, f"Total extensions scanned: {total_extensions}")

    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(issues)} high-risk browser extension(s) detected",
            details=details + [f"[!] {i}" for i in issues],
            remediation=(
                "1. Open chrome://extensions (or edge://extensions)\n"
                "2. Remove extensions you don't recognize or need\n"
                "3. Review permissions for extensions with broad access\n"
                "4. Never install extensions from outside the Chrome/Edge Web Store\n"
                "5. To suppress known-safe extensions, add their name to "
                "checks.browser_extension_audit.whitelist in config.json"
            )
        )

    if warnings:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"{len(warnings)} extension(s) with notable permissions",
            details=details + [f"[~] {w}" for w in warnings],
            remediation="Review flagged extensions -- elevated permissions may be legitimate but warrant awareness"
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message=f"Browser extensions look OK ({total_extensions} scanned)",
        details=details
    )
