"""Optional OS fingerprinting for profiles that explicitly request it."""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from typing import Any

from catnet.nmap.adapter import run_nmap


def detect_os(ip: str, output_base: str, timeout: int = 120) -> dict[str, Any]:
    """Attempt Nmap OS fingerprinting; absence of a match is not a scan failure."""
    safe_ip = re.sub(r"[^A-Za-z0-9_.-]", "_", str(ip))
    os.makedirs(os.path.dirname(output_base) or ".", exist_ok=True)
    xml_file = f"{output_base}_{safe_ip}_os.xml"
    execution = run_nmap(
        ["-O", "--osscan-guess", "--max-os-tries", "1", "-Pn", "-oX", xml_file, ip],
        timeout=timeout,
    )

    if not os.path.exists(xml_file):
        return {
            "matches": [],
            "error": execution["error"] or "Nmap did not create an OS fingerprint XML file.",
            "xml_file": None,
        }
    try:
        root = ET.parse(xml_file).getroot()
    except (ET.ParseError, OSError) as exc:
        return {"matches": [], "error": f"Could not parse OS fingerprint XML: {exc}", "xml_file": xml_file}

    matches: list[dict[str, Any]] = []
    for host_elem in root.findall("host"):
        for match in host_elem.findall("./os/osmatch"):
            try:
                accuracy = int(match.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            matches.append({
                "name": match.get("name", "Unknown OS"),
                "accuracy": accuracy,
                "classes": [
                    {
                        "type": c.get("type", ""),
                        "vendor": c.get("vendor", ""),
                        "family": c.get("osfamily", ""),
                        "generation": c.get("osgen", ""),
                    }
                    for c in match.findall("./osclass")
                ],
            })
    matches.sort(key=lambda item: item["accuracy"], reverse=True)

    error = execution["error"] if execution["returncode"] not in (0, None) else None
    note = None
    if not matches and not error:
        note = (
            "No OS match was returned. Nmap OS fingerprinting may need raw-packet privileges "
            "and generally works best when the target has at least one open and one closed TCP port."
        )
    return {"matches": matches, "error": error, "note": note, "xml_file": xml_file}
