"""Inspect both distributions, then exercise the wheel from an isolated temporary environment."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {"policy", "request", "decision", "test-suite", "batch", "artifact"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    wheels = list(args.dist.glob("*.whl"))
    sources = list(args.dist.glob("*.tar.gz"))
    assert len(wheels) == len(sources) == 1, (
        "use a directory containing exactly one wheel and sdist"
    )
    wheel = wheels[0].resolve()
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        assert all(
            name.startswith("policy_engine/") or name.split("/")[0].endswith(".dist-info")
            for name in names
        )
        assert {f"policy_engine/schemas/{name}.schema.json" for name in SCHEMAS} <= names
        assert "policy_engine/py.typed" in names
        assert any(name.endswith("/licenses/LICENSE") for name in names)
    with tarfile.open(sources[0], "r:gz") as archive:
        names = {name.partition("/")[2] for name in archive.getnames()}
        for directory in ("docs", "examples", "tests", "scripts"):
            assert any(name.startswith(directory + "/") for name in names), directory
        assert "requirements-dev.txt" in names
        assert "scripts/benchmark_policy.py" in names
        assert "docs/PERFORMANCE.md" in names
        assert not any(
            part in {".venv", ".git", "__pycache__", "helix_core"}
            for name in names
            for part in name.split("/")
        )

    with tempfile.TemporaryDirectory(prefix="samsarix-policy-wheel-") as directory:
        workspace = Path(directory)
        venv.EnvBuilder(with_pip=True).create(workspace / "venv")
        executable = (
            workspace / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        )
        subprocess.run(
            [str(executable), "-I", "-m", "pip", "install", "--no-deps", "--no-index", str(wheel)],
            check=True,
            cwd=workspace,
            timeout=180,
        )
        subprocess.run(
            [str(executable), "-I", str(ROOT / "scripts" / "smoke_installed.py"), str(ROOT)],
            check=True,
            cwd=workspace,
            timeout=180,
        )
    print("Wheel inventory, sdist inventory, and isolated installed journeys passed.")


if __name__ == "__main__":
    main()
