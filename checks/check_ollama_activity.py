"""
Check: ollama_activity
Detects unexpected Ollama inference activity when no user session is in
progress — covering loaded VRAM models, active inference requests, GPU
memory anomalies, and recent API traffic in the server log.

Complements check_ollama_exposure.py (which handles network binding).
This check focuses on WHAT Ollama is doing, not WHERE it's listening.

Threat scenarios caught:
  - Rogue process or remote API consumer running inference in the background
  - Model left loaded in VRAM long after last session (resource + stability risk)
  - GPU VRAM spike inconsistent with idle state (e.g. pre-crash condition)
  - Recent POST /api/generate or /api/chat activity without an open UI session
  - Ollama version significantly behind current release (driver compat risk)
"""

import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from engine import CheckResult


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ollama_running() -> bool:
    """Return True if ollama.exe is in the process list."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq ollama.exe", "/NH"],
            capture_output=True, text=True, timeout=5
        )
        return "ollama.exe" in result.stdout
    except Exception:
        return False


def _query_api(endpoint: str, timeout: int = 4) -> dict | None:
    """
    Hit the local Ollama REST API. Returns parsed JSON or None on failure.
    Uses PowerShell Invoke-RestMethod to avoid needing requests library.
    """
    try:
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"(Invoke-RestMethod -Uri 'http://127.0.0.1:11434{endpoint}' "
            f"-Method GET -TimeoutSec {timeout}) | ConvertTo-Json -Depth 5"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        if result.returncode == 0 and result.stdout.strip():
            import json
            return json.loads(result.stdout.strip())
    except Exception:
        pass
    return None


def _get_vram_used_mib() -> int | None:
    """
    Query nvidia-smi for used VRAM in MiB.
    Returns None if nvidia-smi unavailable.
    """
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=6
        )
        if result.returncode == 0:
            return int(result.stdout.strip().split()[0])
    except Exception:
        pass
    return None


def _get_ollama_version() -> str | None:
    """Read installed Ollama version from the running process via API."""
    data = _query_api("/api/version")
    if data and isinstance(data, dict):
        return data.get("version")
    return None


# Oldest Ollama release without CVE-2026-7482 ("Bleeding Llama": unauthenticated heap
# out-of-bounds read via /api/create, fixed in 0.17.1).
MIN_SAFE_OLLAMA = (0, 17, 1)


def _parse_semver(v: str | None) -> tuple | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _below_security_floor(installed: str | None) -> bool:
    parsed = _parse_semver(installed)
    return bool(parsed) and parsed < MIN_SAFE_OLLAMA


def _parse_recent_inference(log_path: Path, lookback_minutes: int) -> list[str]:
    """
    Scan the current Ollama server log for GIN inference POST lines
    within the lookback window.

    Matches lines like:
      [GIN] 2026/05/09 - 13:25:01 | 200 | ... | POST "/api/generate"
      [GIN] 2026/05/09 - 13:25:01 | 200 | ... | POST "/api/chat"
    """
    hits = []
    if not log_path.exists():
        return hits

    cutoff = datetime.now() - timedelta(minutes=lookback_minutes)
    # GIN timestamp format: 2026/05/09 - 13:25:01
    gin_pattern = re.compile(
        r'\[GIN\]\s+(\d{4}/\d{2}/\d{2})\s+-\s+(\d{2}:\d{2}:\d{2})\s+'
        r'\|\s+(\d+)\s+\|.*\|\s+(POST|GET)\s+"(/api/(?:generate|chat|embeddings))"'
    )

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = gin_pattern.search(line)
                if not m:
                    continue
                date_str, time_str, status, method, path = m.groups()
                try:
                    ts = datetime.strptime(f"{date_str} {time_str}", "%Y/%m/%d %H:%M:%S")
                    if ts >= cutoff and method == "POST":
                        hits.append(
                            f"{date_str} {time_str} | HTTP {status} | {method} {path}"
                        )
                except ValueError:
                    continue
    except Exception:
        pass

    return hits


def _find_server_log() -> Path | None:
    """
    Locate the active Ollama server log.
    Ollama rotates: server.log (active session) → server-1.log (previous), etc.
    We check server.log first; fall back to the most recently modified server-N.log.
    """
    log_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Ollama"
    if not log_dir.exists():
        return None

    server_log = log_dir / "server.log"
    if server_log.exists() and server_log.stat().st_size > 0:
        return server_log

    # Find most recent rotated log
    candidates = sorted(
        log_dir.glob("server-*.log"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    return candidates[0] if candidates else None


def _find_app_log() -> Path | None:
    """Locate the active Ollama app log for version/update info."""
    log_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Ollama"
    if not log_dir.exists():
        return None
    app_log = log_dir / "app.log"
    if app_log.exists() and app_log.stat().st_size > 0:
        return app_log
    candidates = sorted(
        log_dir.glob("app-*.log"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    return candidates[0] if candidates else None


def _parse_available_update(app_log: Path | None) -> str | None:
    """
    Scan app log for the most recent 'New update available' line.
    Returns the version string (e.g. 'v0.23.2') or None.
    """
    if not app_log or not app_log.exists():
        return None
    version_pattern = re.compile(r'releases/download/(v[\d.]+)/OllamaSetup\.exe')
    latest = None
    try:
        with open(app_log, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "New update available" in line:
                    m = version_pattern.search(line)
                    if m:
                        latest = m.group(1)
    except Exception:
        pass
    return latest


# ─── Main check ───────────────────────────────────────────────────────────────

def run(config: dict) -> CheckResult:
    check_id = "ollama_activity"
    cfg = config.get("checks", {}).get(check_id, {})
    severity = cfg.get("severity", "MEDIUM")

    # Configurable thresholds (can be set in config.json under checks.ollama_activity)
    lookback_minutes = cfg.get("lookback_minutes", 30)
    vram_idle_threshold_mib = cfg.get("vram_idle_threshold_mib", 500)

    details = []
    warnings = []
    issues = []

    # ── 1. Is Ollama even running? ────────────────────────────────────────────
    if not _ollama_running():
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="Ollama process is not running — no activity to monitor",
            details=["ollama.exe not found in process list"]
        )
    details.append("ollama.exe is running (serve mode)")

    # ── 2. Models currently loaded in VRAM ───────────────────────────────────
    ps_data = _query_api("/api/ps")
    loaded_models = []
    if ps_data is not None:
        models_list = ps_data if isinstance(ps_data, list) else ps_data.get("models", [])
        if isinstance(models_list, list):
            for m in models_list:
                name = m.get("name", "unknown") if isinstance(m, dict) else str(m)
                size_vram = m.get("size_vram", 0) if isinstance(m, dict) else 0
                expires = m.get("expires_at", "") if isinstance(m, dict) else ""
                loaded_models.append(name)
                size_mib = size_vram // (1024 * 1024) if size_vram else 0
                details.append(
                    f"Model loaded in VRAM: {name} "
                    f"({size_mib} MiB, expires: {expires or 'unknown'})"
                )
            if loaded_models:
                warnings.append(
                    f"{len(loaded_models)} model(s) currently loaded in VRAM: "
                    f"{', '.join(loaded_models)} — keepalive may still be active"
                )
        else:
            details.append("api/ps returned unexpected format")
    else:
        details.append("Could not reach Ollama API at http://127.0.0.1:11434/api/ps")

    # ── 3. VRAM usage vs idle baseline ───────────────────────────────────────
    vram_used = _get_vram_used_mib()
    if vram_used is not None:
        details.append(f"GPU VRAM currently used: {vram_used} MiB")
        if vram_used > vram_idle_threshold_mib and not loaded_models:
            issues.append(
                f"VRAM usage is {vram_used} MiB with no model loaded via api/ps — "
                f"possible orphaned GPU allocation (BSOD risk: stop code 0x0000010E territory)"
            )
        elif vram_used > vram_idle_threshold_mib:
            details.append(
                f"VRAM elevated ({vram_used} MiB) — consistent with loaded model"
            )
    else:
        details.append("nvidia-smi unavailable — GPU VRAM check skipped")

    # ── 4. Recent inference activity in server log ────────────────────────────
    server_log = _find_server_log()
    if server_log:
        details.append(f"Scanning server log: {server_log.name}")
        recent_calls = _parse_recent_inference(server_log, lookback_minutes)
        if recent_calls:
            issues.append(
                f"{len(recent_calls)} inference POST(s) found in last {lookback_minutes} min"
            )
            for call in recent_calls[:10]:  # cap detail lines
                details.append(f"  Inference call: {call}")
            if len(recent_calls) > 10:
                details.append(f"  ... and {len(recent_calls) - 10} more")
        else:
            details.append(
                f"No inference activity (POST /api/generate|chat|embeddings) "
                f"in last {lookback_minutes} min"
            )
    else:
        details.append("No Ollama server log found — log scan skipped")

    # ── 5. Version currency check ─────────────────────────────────────────────
    installed_ver = _get_ollama_version()
    app_log = _find_app_log()
    available_ver = _parse_available_update(app_log)

    if installed_ver:
        details.append(f"Installed Ollama version: {installed_ver}")
        if _below_security_floor(installed_ver):
            issues.append(
                f"Ollama {installed_ver} is older than {'.'.join(map(str, MIN_SAFE_OLLAMA))} "
                f"and is affected by CVE-2026-7482 (memory disclosure via /api/create) - update now"
            )
    if available_ver:
        details.append(f"Newer version available: {available_ver}")
        # Parse minor version distance — flag if 2+ minor versions behind
        try:
            def _minor(v):
                parts = v.lstrip("v").split(".")
                return int(parts[1]) if len(parts) > 1 else 0

            inst_minor = _minor(installed_ver or "0.0.0")
            avail_minor = _minor(available_ver)
            if avail_minor - inst_minor >= 2:
                warnings.append(
                    f"Ollama is {avail_minor - inst_minor} minor version(s) behind "
                    f"({installed_ver} → {available_ver}). "
                    f"Outdated versions have known GPU driver compatibility issues."
                )
        except Exception:
            pass

    # ── Determine result ──────────────────────────────────────────────────────
    all_details = details + warnings + issues

    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"Ollama activity anomaly detected: {issues[0]}",
            details=all_details,
            remediation=(
                "If you did not initiate AI inference recently: "
                "(1) Check which process is calling the Ollama API (port 11434). "
                "(2) Run: Invoke-RestMethod http://127.0.0.1:11434/api/ps to see loaded models. "
                "(3) If unexplained, stop Ollama via system tray. "
                "(4) If VRAM is orphaned with no model, reboot to clear GPU state. "
                "(5) Update Ollama — outdated versions have VRAM management bugs (BSOD 0x0000010E)."
            )
        )

    if warnings:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"Ollama running with advisory condition: {warnings[0]}",
            details=all_details,
            remediation=(
                "Review details above. If a model is loaded unexpectedly, "
                "the keepalive window (default 5 min) may not have expired yet. "
                "If Ollama version is outdated, update via: "
                "https://github.com/ollama/ollama/releases/latest"
            )
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="Ollama running idle — no active inference, no VRAM anomalies",
        details=all_details
    )
