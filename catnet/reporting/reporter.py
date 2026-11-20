"""Readable terminal report plus a JSON artefact for later inspection."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Any


class _Colors:
    def __init__(self) -> None:
        enabled = bool(getattr(sys.stdout, "isatty", lambda: False)())
        self.cyan = "\033[96m" if enabled else ""
        self.green = "\033[92m" if enabled else ""
        self.yellow = "\033[93m" if enabled else ""
        self.red = "\033[91m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.reset = "\033[0m" if enabled else ""


def save_json_report(report: dict[str, Any], directory: str = "reports") -> str:
    os.makedirs(directory, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(directory, f"catnet_report_{timestamp}.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    return path


def _version_text(service: dict[str, Any]) -> str:
    pieces = [
        str(service.get("product", "")).strip(),
        str(service.get("version", "")).strip(),
    ]
    text = " ".join(piece for piece in pieces if piece).strip()
    if service.get("extrainfo"):
        text = f"{text} ({service['extrainfo']})" if text else str(service["extrainfo"])
    return text or "Version not identified"


def _print_port_table(ports: list[dict[str, Any]], colors: _Colors) -> None:
    if not ports:
        print("  No open TCP ports were identified in the selected scan scope.")
        return
    headers = ["PORT/PROTO", "STATE", "SERVICE", "PRODUCT / VERSION", "WHY OPEN"]
    rows: list[list[str]] = []
    for port in sorted(ports, key=lambda item: (str(item.get("protocol", "TCP")), int(item.get("port", 0)))):
        rows.append([
            f"{port.get('port', '?')}/{port.get('protocol', 'TCP')}",
            str(port.get("state", "open")).upper(),
            str(port.get("service", "unknown")),
            _version_text(port),
            str(port.get("reason", "") or "Nmap response")[:28],
        ])
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))]
    print("  " + "  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  " + "  ".join("─" * width for width in widths))
    for row in rows:
        printable = [row[i][:widths[i]].ljust(widths[i]) for i in range(len(headers))]
        state_color = colors.green if row[1] == "OPEN" else ""
        print("  " + "  ".join(
            (state_color + printable[i] + colors.reset if i == 1 else printable[i])
            for i in range(len(headers))
        ))
    for port in sorted(ports, key=lambda item: int(item.get("port", 0))):
        for cpe in port.get("cpe", []) or []:
            print(f"    CPE: {cpe}")


def _simple_meaning(port: int, service: str) -> str:
    service = service.lower()
    meanings = {
        "ssh": "Remote command-line administration (SSH)",
        "http": "Web service without transport encryption by default (HTTP)",
        "https": "Encrypted web service (HTTPS/TLS)",
        "domain": "Domain Name System service (DNS)",
        "dns": "Domain Name System service (DNS)",
        "microsoft-ds": "Windows-compatible file/printer sharing (SMB)",
        "netbios-ssn": "Legacy NetBIOS session service; often related to SMB",
        "rdp": "Remote Desktop service",
        "mysql": "MySQL database service",
        "postgresql": "PostgreSQL database service",
        "smtp": "Mail transfer service (SMTP)",
        "ftp": "File transfer service (FTP; not encrypted by default)",
    }
    if service in meanings:
        return meanings[service]
    if "http" in service:
        return "Web application or HTTP endpoint; transport encryption depends on TLS detection"
    if "ssl" in service or "tls" in service or service.endswith("s") and service in {"imaps", "pop3s", "smtps", "ldaps", "ftps"}:
        return "TLS-encrypted application service"
    if "smb" in service or service in {"netbios-ssn", "microsoft-ds"}:
        return "File/printer-sharing service commonly associated with SMB"
    common_ports = {
        22: "Commonly SSH remote administration; verify the detected service name",
        53: "Commonly DNS; verify the detected service name",
        80: "Commonly HTTP web traffic; verify the detected service name",
        443: "Commonly HTTPS/TLS web traffic; verify the detected service name",
        445: "Commonly SMB file/printer sharing; verify the detected service name",
        3389: "Commonly Remote Desktop; verify the detected service name",
    }
    return common_ports.get(int(port), "Open TCP port; purpose depends on the identified service")


def print_report(report: dict[str, Any]) -> None:
    colors = _Colors()
    hosts = report.get("hosts", [])
    all_ports = [port for host in hosts for port in host.get("ports", [])]
    identified = [p for p in all_ports if p.get("service") not in (None, "", "unknown")]
    os_identified = [host for host in hosts if (host.get("classification") or {}).get("os_match")]

    print("\n" + "═" * 78)
    print(f"{colors.bold}{colors.cyan}CATNET  |  NETWORK RECONNAISSANCE REPORT{colors.reset}")
    print("═" * 78)
    print(f"Target scope : {report.get('target', 'Unknown')}")
    print(f"Scan profile : {report.get('profile', 'Unknown')}")
    print(f"Started      : {report.get('started_at', 'Unknown')}")
    print(f"Duration     : {report.get('duration_seconds', 0):.1f} seconds")
    print("─" * 78)
    print("SUMMARY")
    print(f"  Live hosts discovered     : {len(hosts)}")
    print(f"  Open TCP ports             : {len(all_ports)}")
    print(f"  Services identified        : {len(identified)}")
    print(f"  Hosts with OS fingerprint  : {len(os_identified)}")
    print("\nNote: an open port means a service responded; it does not by itself mean the host is vulnerable.")

    for index, host in enumerate(hosts, start=1):
        ip = host.get("ip", host.get("target", "Unknown host"))
        print("\n" + "─" * 78)
        print(f"{colors.bold}{colors.cyan}HOST {index}: {ip}{colors.reset}")
        if host.get("hostnames"):
            print(f"  Hostname(s) : {', '.join(host['hostnames'])}")
        if host.get("mac"):
            vendor = f" ({host['mac_vendor']})" if host.get("mac_vendor") else ""
            print(f"  MAC address : {host['mac']}{vendor}")
        print(f"  Open ports  : {len(host.get('ports', []))}")
        print("\n  EXPOSED SERVICES")
        _print_port_table(host.get("ports", []), colors)

        if host.get("ports"):
            print("\n  WHAT THESE SERVICES GENERALLY MEAN")
            for port in sorted(host["ports"], key=lambda item: int(item.get("port", 0))):
                print(f"  • {port.get('port')}/{port.get('protocol', 'TCP')}: "
                      f"{_simple_meaning(int(port.get('port', 0)), str(port.get('service', 'unknown')))}")

        os_result = host.get("os_result", {}) or {}
        classification = host.get("classification", {}) or {}
        best_os = classification.get("os_match")
        print("\n  OS / HOST TYPE ASSESSMENT")
        if best_os:
            print(f"  Nmap OS guess : {best_os.get('name')} ({best_os.get('accuracy', 0)}% match score)")
        else:
            print("  Nmap OS guess : Not identified")
        print(f"  Assessment    : {classification.get('label', 'Unknown')}")
        print(f"  Confidence    : {classification.get('confidence', 'Low')}")
        if classification.get("evidence"):
            print("  Evidence:")
            for item in classification["evidence"][:6]:
                print(f"    - {item}")
        limitation = classification.get("limitation") or os_result.get("note") or os_result.get("error")
        if limitation:
            print(f"  Limitation    : {limitation}")

        print("\n  PROTOCOL-SPECIFIC METADATA")
        protocol_results = host.get("protocols", []) or []
        if not protocol_results:
            print("  No targeted protocol checks were triggered by the detected service names.")
        for result in protocol_results:
            print(f"  {result.get('protocol')} on port(s) {', '.join(map(str, result.get('ports', [])))}")
            if result.get("error"):
                print(f"    [!] Check failed: {result['error']}")
            if not result.get("scripts") and not result.get("error"):
                print("    No additional metadata returned by the selected script(s).")
            for script in result.get("scripts", []):
                print(f"    [{script.get('id')}] port {script.get('port')}/{script.get('transport')}")
                output = str(script.get("output", "")).strip()
                if output:
                    for line in output.splitlines()[:10]:
                        print(f"      {line[:220]}")

        for warning in host.get("warnings", []) or []:
            print(f"\n  {colors.yellow}[!] {warning}{colors.reset}")
        for error in host.get("errors", []) or []:
            print(f"\n  {colors.red}[ERROR] {error}{colors.reset}")

    if report.get("limitations"):
        print("\n" + "─" * 78)
        print("SCAN LIMITATIONS")
        for item in report["limitations"]:
            print(f"  - {item}")
    print("\n" + "═" * 78)
    print("CatNet reports observations and cautious estimates; it does not prove absence of vulnerabilities.")
    print("═" * 78 + "\n")


def save_html_report(report: dict[str, Any], directory: str = "reports") -> str:
    """Create a self-contained, browser-readable report with no extra dependencies."""
    from html import escape

    os.makedirs(directory, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(directory, f"catnet_report_{timestamp}.html")
    hosts = report.get("hosts", [])
    all_ports = [port for host in hosts for port in host.get("ports", [])]
    identified = [port for port in all_ports if port.get("service") not in (None, "", "unknown")]
    os_count = sum(bool((host.get("classification") or {}).get("os_match")) for host in hosts)

    def e(value: Any) -> str:
        return escape(str(value if value is not None else ""))

    def service_version(port: dict[str, Any]) -> str:
        value = " ".join(part for part in [str(port.get("product", "")).strip(), str(port.get("version", "")).strip()] if part)
        if port.get("extrainfo"):
            value = f"{value} ({port['extrainfo']})" if value else str(port["extrainfo"])
        return value or "Version not identified"

    host_blocks: list[str] = []
    for host in hosts:
        ip = host.get("ip", host.get("target", "Unknown host"))
        hostname = ", ".join(host.get("hostnames", []) or [])
        mac = host.get("mac") or "Not observed"
        if host.get("mac_vendor"):
            mac += f" · {host['mac_vendor']}"
        classification = host.get("classification") or {}
        os_result = host.get("os_result") or {}
        best_os = classification.get("os_match")
        os_guess = f"{best_os.get('name')} ({best_os.get('accuracy')}% match score)" if best_os else "Not identified"

        rows: list[str] = []
        explanations: list[str] = []
        for port in sorted(host.get("ports", []) or [], key=lambda item: (str(item.get("protocol", "TCP")), int(item.get("port", 0)))):
            state = str(port.get("state", "open")).upper()
            state_class = "open" if state == "OPEN" else "neutral"
            rows.append(
                "<tr>"
                f"<td><strong>{e(port.get('port'))}/{e(port.get('protocol', 'TCP'))}</strong></td>"
                f"<td><span class='state {state_class}'>{e(state)}</span></td>"
                f"<td>{e(port.get('service', 'unknown'))}</td>"
                f"<td>{e(service_version(port))}</td>"
                f"<td>{e(port.get('reason') or 'Nmap response')}</td>"
                "</tr>"
            )
            explanations.append(
                f"<li><strong>{e(port.get('port'))}/{e(port.get('protocol', 'TCP'))} — {e(port.get('service', 'unknown'))}:</strong> "
                f"{e(_simple_meaning(int(port.get('port', 0)), str(port.get('service', 'unknown'))))}</li>"
            )
            for cpe in port.get("cpe", []) or []:
                explanations.append(f"<li><strong>CPE:</strong> {e(cpe)}</li>")
        if not rows:
            rows.append("<tr><td colspan='5' class='muted'>No open TCP ports identified in this scan scope.</td></tr>")

        protocol_cards: list[str] = []
        for result in host.get("protocols", []) or []:
            protocol_cards.append(
                f"<div class='protocol'><h4>{e(result.get('protocol'))} · port(s) {e(', '.join(map(str, result.get('ports', []))))}</h4>"
            )
            if result.get("error"):
                protocol_cards.append(f"<p class='warning'>{e(result['error'])}</p>")
            if not result.get("scripts") and not result.get("error"):
                protocol_cards.append("<p class='muted'>The selected metadata scripts returned no additional output.</p>")
            for script in result.get("scripts", []) or []:
                protocol_cards.append(f"<p><strong>{e(script.get('id'))}</strong> <span class='muted'>port {e(script.get('port'))}/{e(script.get('transport'))}</span></p>")
                protocol_cards.append(f"<pre>{e(script.get('output') or 'No output')}</pre>")
            protocol_cards.append("</div>")
        if not protocol_cards:
            protocol_cards.append("<p class='muted'>No protocol-specific checks were triggered by the detected services or the selected profile.</p>")

        notices = []
        for warning in host.get("warnings", []) or []:
            notices.append(f"<div class='notice warning'>⚠ {e(warning)}</div>")
        for error in host.get("errors", []) or []:
            notices.append(f"<div class='notice error'>✕ {e(error)}</div>")

        host_blocks.append(f"""
        <section class="host card">
          <div class="host-head"><div><p class="eyebrow">HOST</p><h2>{e(ip)}</h2><p class="muted">{e(hostname or 'Hostname not observed')} · MAC: {e(mac)}</p></div>
          <div class="pill">{len(host.get('ports', []) or [])} open port(s)</div></div>
          <div class="host-facts"><div><span>OS fingerprint</span><strong>{e(os_guess)}</strong></div><div><span>Assessment</span><strong>{e(classification.get('label', 'Unknown'))}</strong></div><div><span>Confidence</span><strong>{e(classification.get('confidence', 'Low'))}</strong></div></div>
          <h3>Exposed services</h3><div class="table-wrap"><table><thead><tr><th>Port / transport</th><th>State</th><th>Service</th><th>Product / version</th><th>Reason</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
          <details><summary>What these services generally mean</summary><ul>{''.join(explanations)}</ul></details>
          <details><summary>Classification evidence and limitations</summary><ul>{''.join(f'<li>{e(item)}</li>' for item in classification.get('evidence', []) or [])}</ul><p class="muted">{e(classification.get('limitation') or os_result.get('note') or os_result.get('error') or 'OS information is an estimate when present.')}</p></details>
          <h3>Protocol-specific metadata</h3>{''.join(protocol_cards)}
          {''.join(notices)}
        </section>""")

    limitation_items = "".join(f"<li>{e(item)}</li>" for item in report.get("limitations", []) or [])
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CatNet Scan Report — {e(report.get('target', 'target'))}</title>
<style>
:root{{--bg:#0b1220;--panel:#121d30;--panel2:#17253a;--line:#263750;--text:#edf4ff;--muted:#a8b7cb;--accent:#55d6be;--blue:#83b7ff;--warn:#f4ca72;--danger:#ff8585}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(ellipse at top,#14243b 0,#0b1220 48%);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}main{{max-width:1180px;margin:0 auto;padding:34px 22px 64px}}.hero{{padding:30px 30px 26px;border:1px solid var(--line);border-radius:22px;background:linear-gradient(120deg,#172a40,#101b2c 75%);box-shadow:0 18px 55px #0003}}.eyebrow{{margin:0 0 6px;color:var(--accent);font-size:11px;letter-spacing:.18em;font-weight:800}}h1{{font-size:clamp(28px,4vw,42px);line-height:1.12;margin:0 0 12px}}h2{{margin:0;font-size:24px}}h3{{margin:26px 0 12px;font-size:17px}}h4{{margin:0 0 10px;color:var(--accent)}}.subtitle,.muted{{color:var(--muted)}}.subtitle{{margin:0}}.meta{{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}}.meta span,.pill{{background:#20334c;border:1px solid #304764;border-radius:100px;padding:6px 11px;color:#cfe0f6;font-size:12px}}.stats{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:16px 0 30px}}.stat,.card{{border:1px solid var(--line);background:linear-gradient(160deg,var(--panel),#101a2a);border-radius:18px}}.stat{{padding:18px}}.stat span,.host-facts span{{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}}.stat strong{{font-size:30px;letter-spacing:-.03em}}.host{{padding:24px;margin:16px 0}}.host-head{{display:flex;justify-content:space-between;align-items:center;gap:16px}}.host-head .muted{{margin:4px 0 0}}.host-facts{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:20px 0;padding:16px;background:#0d1727;border:1px solid var(--line);border-radius:12px}}.host-facts strong{{font-size:14px;overflow-wrap:anywhere}}.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:12px}}table{{width:100%;border-collapse:collapse;min-width:760px;font-size:13px}}th{{text-align:left;color:var(--muted);background:#0d1727;font-weight:650}}th,td{{padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}}tr:last-child td{{border-bottom:0}}.state{{display:inline-block;border-radius:40px;padding:2px 8px;font-size:10px;font-weight:800;letter-spacing:.06em}}.state.open{{background:#123f3c;color:#78ead2}}.state.neutral{{background:#303b4e;color:#d6dfed}}details{{margin:14px 0;background:#0d1727;border:1px solid var(--line);border-radius:12px;padding:12px 14px}}summary{{cursor:pointer;color:var(--blue);font-weight:700}}details ul{{padding-left:22px}}.protocol{{padding:14px;margin:10px 0;border:1px solid var(--line);border-radius:12px;background:#0d1727}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#c8d8ea;background:#080f1b;padding:12px;border-radius:8px;font:12px/1.55 ui-monospace,SFMono-Regular,monospace}}.notice{{margin-top:10px;padding:10px 12px;border-radius:10px}}.warning{{color:var(--warn);background:#392e19;border:1px solid #58472b}}.error{{color:var(--danger);background:#3b202a;border:1px solid #63313d}}.foot{{margin-top:26px;padding:18px 4px;color:var(--muted);font-size:12px}}@media(max-width:760px){{main{{padding:16px 12px 36px}}.hero{{padding:22px}}.stats{{grid-template-columns:repeat(2,minmax(0,1fr))}}.host{{padding:16px}}.host-facts{{grid-template-columns:1fr}}.host-head{{align-items:flex-start;flex-direction:column}}}}
</style></head><body><main>
<header class="hero"><p class="eyebrow">NETWORK RECONNAISSANCE</p><h1>CatNet Scan Report</h1><p class="subtitle">A readable summary of reachable hosts, exposed ports, identified services, and evidence-based OS estimates.</p>
<div class="meta"><span>Target: {e(report.get('target'))}</span><span>Profile: {e(report.get('profile'))}</span><span>Started: {e(report.get('started_at'))}</span><span>Duration: {e(report.get('duration_seconds'))} s</span></div></header>
<div class="stats"><div class="stat"><span>Responsive hosts</span><strong>{len(hosts)}</strong></div><div class="stat"><span>Open TCP ports</span><strong>{len(all_ports)}</strong></div><div class="stat"><span>Services identified</span><strong>{len(identified)}</strong></div><div class="stat"><span>OS fingerprints matched</span><strong>{os_count}</strong></div></div>
<h2>Host findings</h2>{''.join(host_blocks)}
<section class="foot"><h3>Scope and limitations</h3><ul>{limitation_items}</ul><p>An open port means that a service responded to this scan; it does not by itself mean the service is vulnerable. OS fingerprints are estimates, and firewalls can hide services. Only scan systems you own or are authorized to assess.</p><p>Generated by CatNet · Python + Nmap</p></section>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(document)
    return path
