"""Small, reusable wrapper for executing Nmap safely and reporting failures."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any


def run_nmap(arguments: list[str], timeout: int = 300) -> dict[str, Any]:
    """Run Nmap and return diagnostics instead of hiding stderr or exceptions."""
    command = ["nmap", *[str(arg) for arg in arguments]]
    if shutil.which("nmap") is None:
        return {
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "Nmap was not found on PATH. Install Nmap and verify `nmap --version`.",
        }

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        error = None
        if completed.returncode != 0:
            error = (
                completed.stderr.strip()
                or completed.stdout.strip()
                or f"Nmap exited with status {completed.returncode}."
            )
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "error": error,
        }
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": f"Nmap timed out after {timeout} seconds.",
        }
    except OSError as exc:
        return {
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": f"Could not launch Nmap: {exc}",
        }
