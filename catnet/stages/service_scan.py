"""Stage 3a: identify services and version hints on ports already found open."""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from typing import Any

from catnet.nmap.adapter import run_nmap


def _safe_target_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(target))


def _extract_services(root: ET.Element) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    for host_elem in root.findall("host"):
        for port_elem in host_elem.findall("./ports/port"):
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            if state != "open":
                continue
            service_elem = port_elem.find("service")
            service_elem = service_elem if service_elem is not None else ET.Element("service")
            cpes = [node.text.strip() for node in service_elem.findall("cpe") if node.text and node.text.strip()]
            scripts = [
                {"id": script.get("id", "script"), "output": script.get("output", "")}
                for script in port_elem.findall("script")
            ]
            services.append({
                "port": int(port_elem.get("portid", "0")),
                "protocol": port_elem.get("protocol", "unknown").upper(),
                "state": state,
                "service": service_elem.get("name", "unknown") or "unknown",
                "product": service_elem.get("product", "") or "",
                "version": service_elem.get("version", "") or "",
                "extrainfo": service_elem.get("extrainfo", "") or "",
                "tunnel": service_elem.get("tunnel", "") or "",
                "method": service_elem.get("method", "") or "",
                "confidence": service_elem.get("conf", "") or "",
                "cpe": cpes,
                "scripts": scripts,
            })
    services.sort(key=lambda item: (item["protocol"], item["port"]))
    return services


def service_scan(
    ip: str,
    open_ports: list[Any],
    output_base: str | None = None,
    timeout: int = 180,
) -> dict[str, Any]:
    """Run Nmap version detection only against ports confirmed open in Stage 2."""
    port_ids: set[int] = set()
    for item in open_ports:
        try:
            port_ids.add(int(item.get("port")) if isinstance(item, dict) else int(item))
        except (TypeError, ValueError):
            continue

    if not port_ids:
        return {"target": ip, "services": [], "error": None, "skipped": True}

    if output_base is None:
        output_base = "catnet_scan"
    os.makedirs(os.path.dirname(output_base) or ".", exist_ok=True)
    xml_file = f"{output_base}_{_safe_target_name(ip)}_services.xml"
    port_arg = ",".join(str(port) for port in sorted(port_ids))
    args = ["-sT", "-sV", "--version-light", "-Pn", "-p", port_arg, "-oX", xml_file, ip]
    execution = run_nmap(args, timeout=timeout)

    if not os.path.exists(xml_file):
        return {
            "target": ip, "services": [],
            "error": execution["error"] or "Nmap did not create a service XML file.",
            "skipped": False, "command": execution["command"],
        }
    try:
        root = ET.parse(xml_file).getroot()
    except (ET.ParseError, OSError) as exc:
        return {"target": ip, "services": [], "error": f"Could not parse service XML: {exc}", "skipped": False}

    services = _extract_services(root)
    warning = execution["error"] if execution["returncode"] not in (0, None) else None
    return {
        "target": ip,
        "services": services,
        "error": None,
        "warning": warning,
        "skipped": False,
        "command": execution["command"],
        "xml_file": xml_file,
    }
