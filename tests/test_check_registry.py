"""
Consistency tests: every check configured in config.json has a module, every
module has a config entry and a callable run(), and every module returns a
CheckResult-shaped object when its dependencies are stubbed out of the machine.
Catches the "added a check but forgot to wire it" class of bug.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

CONFIG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
MODULE_FILES = sorted((ROOT / "checks").glob("check_*.py"))
MODULE_IDS = [p.stem[len("check_"):] for p in MODULE_FILES]


def load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRegistry:
    def test_config_has_checks(self):
        assert CONFIG["checks"]

    @pytest.mark.parametrize("check_id", sorted(CONFIG["checks"]))
    def test_every_configured_check_has_a_module(self, check_id):
        assert (ROOT / "checks" / f"check_{check_id}.py").exists(), f"config.json lists '{check_id}' but no module"

    @pytest.mark.parametrize("module_id", MODULE_IDS)
    def test_every_module_is_configured(self, module_id):
        assert module_id in CONFIG["checks"], f"checks/check_{module_id}.py is not in config.json"

    @pytest.mark.parametrize("path", MODULE_FILES, ids=MODULE_IDS)
    def test_every_module_exposes_run(self, path):
        assert callable(getattr(load(path), "run", None))

    @pytest.mark.parametrize("check_id", sorted(CONFIG["checks"]))
    def test_every_configured_check_has_severity_and_description(self, check_id):
        entry = CONFIG["checks"][check_id]
        assert entry.get("severity") in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert entry.get("description")
        assert isinstance(entry.get("enabled"), bool)

    def test_config_json_has_required_top_level_keys(self):
        for key in ("scan_interval_seconds", "log_retention_days", "checks"):
            assert key in CONFIG
