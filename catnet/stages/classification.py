"""Conservative, evidence-backed host classification."""

from __future__ import annotations

from typing import Any


def classify_host(
    os_result: dict[str, Any] | None = None,
    services: list[dict[str, Any]] | None = None,
    hostname: str | None = None,
    mac_vendor: str | None = None,
    os_skipped_reason: str | None = None,
) -> dict[str, Any]:
    """Classify only when scan evidence supports a tentative OS-family claim."""
    os_result = os_result or {}
    services = services or []
    matches = os_result.get("matches", []) or []
    evidence: list[str] = []

    if hostname:
        evidence.append(f"Observed hostname: {hostname}")
    if mac_vendor:
        evidence.append(f"MAC vendor string: {mac_vendor} (vendor alone does not prove device type)")

    for service in services:
        name = str(service.get("service", "unknown"))
        product = str(service.get("product", ""))
        version = str(service.get("version", ""))
        if name != "unknown" or product:
            label = f"{service.get('port', '?')}/{service.get('protocol', 'TCP')}: {name}"
            if product:
                label += f" ({product} {version})".rstrip()
            evidence.append(f"Detected service: {label}")

    if not matches:
        reason = os_result.get("error") or os_result.get("note") or os_skipped_reason
        return {
            "label": "Unknown — insufficient OS evidence",
            "confidence": "Low",
            "os_match": None,
            "evidence": evidence,
            "limitation": reason or "No OS fingerprint matched this host.",
        }

    best = sorted(matches, key=lambda item: int(item.get("accuracy", 0)), reverse=True)[0]
    name = str(best.get("name", "Unknown OS"))
    normalized = name.lower()
    accuracy = int(best.get("accuracy", 0))

    if any(token in normalized for token in ("windows", "microsoft windows")):
        label = "Likely Windows host"
    elif any(token in normalized for token in ("linux", "gnu/linux")):
        label = "Likely Linux-based host"
    elif any(token in normalized for token in ("mac os", "macos", "mac os x", "ios", "darwin")):
        label = "Likely Apple OS host"
    elif any(token in normalized for token in ("router", "network appliance", "cisco", "juniper", "mikrotik", "fortinet", "ubiquiti")):
        label = "Likely network appliance"
    elif any(token in normalized for token in ("embedded", "espressif", "openwrt", "dd-wrt")):
        label = "Likely embedded / IoT-class host"
    else:
        label = f"Likely {name}"

    if accuracy >= 95:
        confidence = "High"
    elif accuracy >= 85:
        confidence = "Medium"
    else:
        confidence = "Low"

    evidence.insert(0, f"Nmap OS fingerprint: {name} ({accuracy}% match score)")
    return {
        "label": label,
        "confidence": confidence,
        "os_match": best,
        "evidence": evidence,
        "limitation": "OS match scores are fingerprint estimates, not proof of the exact device or version.",
    }
