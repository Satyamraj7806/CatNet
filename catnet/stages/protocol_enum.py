"""Stage 4: run small, service-specific Nmap NSE checks only when relevant."""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from typing import Any

from catnet.nmap.adapter import run_nmap


def _safe_target_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(target))


def _script_outputs(xml_file: str) -> list[dict[str, str]]:
    root = ET.parse(xml_file).getroot()
    outputs: list[dict[str, str]] = []
    for host_elem in root.findall("host"):
        for port_elem in host_elem.findall("./ports/port"):
            port_id = port_elem.get("portid", "?")
            protocol = port_elem.get("protocol", "?").upper()
            for script in port_elem.findall("script"):
                outputs.append({
                    "port": str(port_id),
                    "transport": protocol,
                    "id": script.get("id", "script"),
                    "output": script.get("output", "No script output."),
                })
        for script in host_elem.findall("./hostscript/script"):
            outputs.append({
                "port": "host",
                "transport": "host",
                "id": script.get("id", "script"),
                "output": script.get("output", "No script output."),
            })
    return outputs


def enumerate_protocols(
    ip: str,
    services: list[dict[str, Any]],
    output_base: str,
    timeout: int = 60,
) -> list[dict[str, Any]]:
    """Collect metadata for confirmed HTTP, TLS, SMB, and RPC services.

    This deliberately avoids broad/default NSE script execution. It is metadata
    collection, not a vulnerability scan.
    """
    groups: dict[str, dict[str, Any]] = {}

    def add_group(label: str, script_names: list[str], port: int) -> None:
        group = groups.setdefault(label, {"protocol": label, "scripts": script_names, "ports": set()})
        group["ports"].add(int(port))

    secure_services = {"https", "https-alt", "imaps", "pop3s", "smtps", "ftps", "ldaps", "mqtts"}
    for item in services:
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        name = str(item.get("service", "")).lower()
        product = str(item.get("product", "")).lower()
        tunnel = str(item.get("tunnel", "")).lower()
        combined = f"{name} {product}"

        if "http" in combined:
            add_group("HTTP", ["http-title", "http-server-header"], port)
        if name in secure_services or tunnel == "ssl" or "https" in name or name.startswith("ssl/"):
            add_group("TLS", ["ssl-cert"], port)
        if any(token in combined for token in ("smb", "microsoft-ds", "netbios-ssn", "samba")):
            add_group("SMB", ["smb-os-discovery", "smb-protocols"], port)
        if any(token in combined for token in ("rpcbind", "sunrpc", "msrpc")):
            add_group("RPC", ["rpcinfo"], port)

    if not groups:
        return []

    results: list[dict[str, Any]] = []
    os.makedirs(os.path.dirname(output_base) or ".", exist_ok=True)
    for index, (label, group) in enumerate(groups.items(), start=1):
        ports = sorted(group["ports"])
        port_arg = ",".join(str(port) for port in ports)
        safe_ip = _safe_target_name(ip)
        xml_file = f"{output_base}_{safe_ip}_protocol_{index}.xml"
        args = [
            "-sT", "-sV", "--version-light", "-Pn", "--script", ",".join(group["scripts"]),
            "-p", port_arg, "-oX", xml_file, ip,
        ]
        execution = run_nmap(args, timeout=timeout)
        scripts: list[dict[str, str]] = []
        error = None
        if not os.path.exists(xml_file):
            error = execution["error"] or "Nmap did not create a protocol metadata XML file."
        else:
            try:
                scripts = _script_outputs(xml_file)
            except (ET.ParseError, OSError) as exc:
                error = f"Could not parse protocol metadata XML: {exc}"
        if execution["returncode"] not in (0, None) and error is None:
            error = execution["error"]
        results.append({
            "protocol": label,
            "ports": ports,
            "scripts_requested": group["scripts"],
            "scripts": scripts,
            "error": error,
        })
    return results
