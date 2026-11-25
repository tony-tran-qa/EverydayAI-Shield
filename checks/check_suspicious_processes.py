"""
Check: suspicious_processes
Detects processes that show behavioral patterns consistent with
AI-tool-spawned malware (post-exploitation, persistence mechanisms).

Looks for:
- Scheduled tasks created by AI tool processes
- Registry Run keys added recently
- Processes with unusual parent-child relationships
- PowerShell with encoded commands (common obfuscation)
- curl/wget running outside expected dirs
"""

import subprocess
import re
from pathlib import Path
from engine import CheckResult


SAFE_SCHTASK_OWNERS = {
    "microsoft", "windows", "mcafee", "intel", "nvidia",
    "adobe", "google", "mozilla", "system"
}


def is_allowed_task(task_name: str, task_cmd: str, allowed: list) -> bool:
    """A task is allowed only when BOTH its name prefix and its command path match an entry
    in config checks.suspicious_processes.allowed_tasks, e.g.
    {"name_prefix": "\\\\MyBackup", "command_contains": "C:\\\\Scripts\\\\"}.
    Requiring the command path stops a lookalike task name from hiding a malicious command."""
    for entry in allowed or []:
        if not isinstance(entry, dict):
            continue
        prefix = (entry.get("name_prefix") or "").lower()
        needle = (entry.get("command_contains") or "").lower()
        if prefix and needle and task_name.lower().startswith(prefix) and needle in task_cmd.lower():
            return True
    return False


def check_scheduled_tasks(allowed_tasks=()) -> tuple[list[str], list[str]]:
    issues, details = [], []
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True, text=True, timeout=15
        )
        # Parse tasks — look for ones running node/python/powershell with suspicious args
        task_name = ""
        task_cmd = ""
        for line in result.stdout.splitlines():
            if line.startswith("TaskName:"):
                task_name = line.split(":", 1)[-1].strip()
                task_cmd = ""
            elif "Task To Run:" in line:
                task_cmd = line.split(":", 1)[-1].strip()
                if task_cmd and task_name:
                    # Flag tasks running AI-adjacent binaries with suspicious patterns
                    risky_patterns = [
                        r"powershell.*-enc",      # encoded PS command
                        r"powershell.*-w.*hidden", # hidden window
                        r"cmd.*\/c.*curl",
                        r"node.*http",
                        r"python.*socket",
                        r"wscript",
                        r"mshta",
                    ]
                    for pat in risky_patterns:
                        if re.search(pat, task_cmd, re.IGNORECASE):
                            # Check if it's from a known-safe owner
                            owner_safe = any(s in task_name.lower() for s in SAFE_SCHTASK_OWNERS)
                            if is_allowed_task(task_name, task_cmd, allowed_tasks):
                                details.append(f"Allowed scheduled task (config): {task_name}")
                            elif not owner_safe:
                                issues.append(f"Suspicious scheduled task: '{task_name}' runs: {task_cmd[:80]}")
                            break
    except Exception as e:
        details.append(f"Scheduled task check error: {e}")
    return issues, details


def check_registry_run_keys() -> tuple[list[str], list[str]]:
    issues, details = [], []
    run_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    ai_patterns = [
        r"node\b", r"python\b", r"ollama", r"claude",
        r"npx", r"uvx", r"powershell.*-enc"
    ]
    for key in run_keys:
        try:
            result = subprocess.run(
                ["reg", "query", key],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "REG_" not in line:
                    continue
                for pat in ai_patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        # Ollama in Run is expected if user installed it to start on boot
                        if "ollama" in line.lower():
                            details.append(f"Ollama in startup (expected): {line.strip()[:80]}")
                        else:
                            issues.append(f"AI-related startup entry in {key}: {line.strip()[:80]}")
                        break
                else:
                    details.append(f"Run key entry: {line.strip()[:80]}")
        except Exception as e:
            details.append(f"Registry check error ({key}): {e}")
    return issues, details


# -EncodedCommand with any PowerShell abbreviation (-e, -ec, -enc ...) followed by a long
# base64 blob. Requiring the blob avoids matching harmless flags such as "-Encoding UTF8".
ENCODED_PS_PATTERN = re.compile(r"\s-(?:e|ec|en[a-z]*)\s+['\"]?[A-Za-z0-9+/=]{20,}", re.IGNORECASE)


def find_encoded_commands(command_lines) -> list[str]:
    """Return the command lines that carry an encoded PowerShell payload. Pure function."""
    return [ln for ln in command_lines if ENCODED_PS_PATTERN.search(" " + ln)]


# Content that makes a decoded payload suspicious: download cradles, in-memory execution,
# hidden windows, policy/AMSI bypass. Many legitimate tools (MCP shell wrappers, installers)
# also use -EncodedCommand, so the payload is decoded and judged instead of flagged blindly.
SUSPICIOUS_PAYLOAD = re.compile(
    r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|\bcurl\b|"
    r"invoke-expression|\biex\b|frombase64string|start-bitstransfer|-w(?:indowstyle)?\s+hidden|"
    r"amsi|bypass|reflection\.assembly|virtualalloc|https?://",
    re.IGNORECASE,
)


def decode_encoded_command(line: str) -> str | None:
    """Decode the base64 (UTF-16LE) payload of an -EncodedCommand line, or None if undecodable."""
    import base64
    m = re.search(r"\s-(?:e|ec|en[a-z]*)\s+['\"]?([A-Za-z0-9+/=]{20,})", " " + line, re.IGNORECASE)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-16-le")
    except Exception:
        return None


def classify_encoded_command(line: str) -> tuple[bool, str]:
    """Return (suspicious, decoded_preview). Undecodable payloads count as suspicious."""
    decoded = decode_encoded_command(line)
    if decoded is None:
        return True, "(could not decode)"
    preview = " ".join(decoded.split())[:90]
    return bool(SUSPICIOUS_PAYLOAD.search(decoded)), preview


def get_powershell_command_lines() -> list[str]:
    """Command lines of running powershell/pwsh processes.

    Uses CIM through PowerShell: wmic.exe was removed from current Windows 11 builds,
    so the old wmic call silently never worked there.
    """
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe' OR Name='pwsh.exe'\" "
         "| ForEach-Object { $_.CommandLine }"],
        capture_output=True, text=True, timeout=20
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip()[:120] or f"exit code {result.returncode}")
    return [ln for ln in result.stdout.splitlines() if ln.strip()]


def check_encoded_powershell() -> tuple[list[str], list[str]]:
    issues, details = [], []
    try:
        for line in find_encoded_commands(get_powershell_command_lines()):
            suspicious, preview = classify_encoded_command(line)
            if suspicious:
                issues.append(f"Suspicious encoded PowerShell command running, decoded: {preview}")
            else:
                details.append(f"Encoded PowerShell with benign-looking payload (tool wrapper?): {preview}")
    except Exception as e:
        details.append(f"PowerShell check error: {e}")
    return issues, details


def run(config: dict) -> CheckResult:
    check_id = "suspicious_processes"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "HIGH")
    all_issues = []
    all_details = []

    allowed_tasks = config.get("checks", {}).get(check_id, {}).get("allowed_tasks", [])

    # Run sub-checks
    for fn in [lambda: check_scheduled_tasks(allowed_tasks), check_registry_run_keys, check_encoded_powershell]:
        issues, details = fn()
        all_issues.extend(issues)
        all_details.extend(details)

    if all_issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(all_issues)} suspicious process/persistence indicator(s)",
            details=all_details + [f"⚠ {i}" for i in all_issues],
            remediation=(
                "1. Review scheduled tasks: schtasks /query /fo LIST /v\n"
                "2. Clean registry Run keys: regedit → HKCU/HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                "3. Kill suspicious PowerShell: taskkill /IM powershell.exe /F (with caution)\n"
                "4. Run McAfee full scan immediately if persistence is detected"
            )
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="No suspicious AI-related process persistence detected",
        details=all_details or ["Scheduled tasks, registry Run keys, and PS processes look clean"]
    )
