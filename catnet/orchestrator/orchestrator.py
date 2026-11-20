"""CatNet pipeline with structured, human-readable Nmap results."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from catnet.stages.discovery import run_discovery
from catnet.stages.portscan import port_scan


def _format_duration(seconds):
    try:
        seconds = max(0, int(float(seconds)))
    except (TypeError, ValueError):
        return "unknown"
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def _print_host_report(ip, result, profile):
    info = result.get("host_info", {})
    ports = result.get("ports", [])
    summary = result.get("port_summary", {})

    print("\n" + "=" * 78)
    print(f"  CATNET SCAN REPORT  |  {ip}")
    print("=" * 78)
    print(f"  Scan profile : {profile.get('name', 'Nmap scan')}")
    print(f"  Host status  : {info.get('status', 'unknown').upper()}")

    if info.get("hostnames"):
        print(f"  Hostname(s)  : {', '.join(info['hostnames'])}")
    if info.get("mac"):
        vendor = f" ({info['mac_vendor']})" if info.get("mac_vendor") else ""
        print(f"  MAC address  : {info['mac']}{vendor}")
    if info.get("distance") is not None:
        print(f"  Hop distance : {info['distance']} hop(s), as estimated by Nmap")

    print("\n  PORT AND SERVICE DETAILS")
    print("  " + "-" * 74)
    if not ports:
        print("  No open ports detected in this scan.")
    else:
        print(f"  {'PORT':<13}{'NMAP SERVICE':<19}{'LIKELY APPLICATION / ROLE':<43}PRODUCT / VERSION")
        print("  " + "-" * 112)
        for port in sorted(ports, key=lambda item: (item.get("protocol", "tcp"), int(item.get("port", 0)))):
            endpoint = f"{port.get('port', '?')}/{port.get('protocol', 'tcp')}"
            service = port.get("service") or "unknown"
            if port.get("tunnel"):
                service = f"{port['tunnel']}/{service}"

            details = " ".join(
                part for part in (port.get("product", ""), port.get("version", "")) if part
            )
            if port.get("extrainfo"):
                details = f"{details} ({port['extrainfo']})" if details else port["extrainfo"]
            if not details:
                details = "Product/version not identified"
            role = port.get("application_role") or "Unclassified service"
            confidence = port.get("role_confidence", "")
            print(f"  {endpoint:<13}{service[:18]:<19}{role[:42]:<43}{details}")
            print(f"  {'':13}Identification: {confidence}; {port.get('role_basis', 'basis unavailable')}")
            if port.get("cpe"):
                print(f"  {'':13}CPE: {', '.join(port['cpe'])}")
            for script_result in port.get("scripts", []):
                output = script_result.get("output", "").replace("\r", " ").replace("\n", " | ").strip()
                if len(output) > 260:
                    output = output[:257] + "..."
                print(f"  {'':13}NSE {script_result.get('id', 'script')}: {output}")

        print("\n  APPLICATION / SERVICE SUMMARY")
        print("  " + "-" * 74)
        for port in sorted(ports, key=lambda item: (item.get("protocol", "tcp"), int(item.get("port", 0)))):
            endpoint = f"{port.get('port', '?')}/{port.get('protocol', 'tcp')}"
            role = port.get("application_role", "Unclassified service")
            print(f"  - {role} on {endpoint} ({port.get('service', 'unknown')})")

    print("\n  OS DETECTION")
    print("  " + "-" * 74)
    os_matches = info.get("os_matches", [])
    if os_matches:
        for index, match in enumerate(os_matches, start=1):
            print(f"  {index}. {match.get('name', 'Unknown OS')} (confidence: {match.get('accuracy', '?')}%)")
            if match.get("classes"):
                first_class = match["classes"][0]
                parts = [first_class.get("vendor"), first_class.get("family"), first_class.get("generation"), first_class.get("type")]
                description = " / ".join(value for value in parts if value)
                if description:
                    print(f"     Classification: {description}")
    else:
        print("  No confident OS match returned by Nmap.")
        print("  OS detection is a fingerprint-based estimate; it may need open and closed ports to match.")

    host_scripts = info.get("scripts", [])
    if host_scripts:
        print("\n  HOST-LEVEL SERVICE DISCOVERY")
        print("  " + "-" * 74)
        for item in host_scripts:
            output = item.get("output", "").replace("\r", " ").replace("\n", " | ").strip()
            if len(output) > 300:
                output = output[:297] + "..."
            print(f"  - {item.get('id', 'script')}: {output}")

    uptime = info.get("uptime")
    if uptime and (uptime.get("seconds") or uptime.get("lastboot")):
        print("\n  HOST UPTIME ESTIMATE")
        if uptime.get("seconds"):
            print(f"  Estimated uptime: {_format_duration(uptime['seconds'])}")
        if uptime.get("lastboot"):
            print(f"  Last boot: {uptime['lastboot']}")

    open_count = summary.get("open", len(ports))
    closed_count = summary.get("closed", 0)
    filtered_count = summary.get("filtered", 0)
    print("\n  SCAN SUMMARY")
    print("  " + "-" * 74)
    print(f"  Open ports: {open_count} | Closed: {closed_count} | Filtered: {filtered_count}")
    print(f"  Duration  : {_format_duration(result.get('elapsed_seconds'))}")
    if result.get("xml_file"):
        print(f"  Raw XML   : {result['xml_file']}")
    print("=" * 78)


def run_pipeline(target, profile):
    """CatNet scanning pipeline: discovery, concurrent port scans, rich report."""
    output_base = f"catnet_scan_{int(time.time())}"

    print("\n[STAGE 1] Host Discovery")
    print("-" * 28)
    print(f"[INFO] Discovering hosts for: {target}")
    discovery_result = run_discovery(output_base, target)

    if discovery_result.get("error"):
        print(f"[ERROR] {discovery_result['error']}")
        return

    hosts = discovery_result.get("hosts", [])
    if not hosts:
        print("[INFO] No live hosts found.")
        return

    print(f"[INFO] {len(hosts)} host(s) discovered:\n")
    for host in hosts:
        print(f"  [+] Host up: {host['target']}")

    print("\n[STAGE 2] Port Scanning")
    print("-" * 28)
    print(f"[INFO] Profile: {profile.get('name', 'Nmap scan')}")
    print(f"[INFO] Scanning {len(hosts)} host(s). Live progress follows below.")

    port_results = {}
    max_workers = min(5, len(hosts))
    inline_progress = len(hosts) == 1

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(port_scan, host, output_base, profile, inline_progress): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            ip = host["target"]
            try:
                result = future.result()
            except Exception as exc:
                print(f"[ERROR] Scan task failed for {ip}: {exc}")
                port_results[ip] = {"target": ip, "error": str(exc)}
                continue

            port_results[ip] = result
            if result.get("error"):
                print(f"[ERROR] {ip}: {result['error']}")

    print("\n[STAGE 3] Scan Results")
    print("-" * 28)
    for host in hosts:
        ip = host["target"]
        result = port_results.get(ip)
        if not result:
            print(f"\n[!] No result was produced for {ip}.")
            continue
        if result.get("error"):
            print(f"\n[!] Could not create report for {ip}: {result['error']}")
            continue
        _print_host_report(ip, result, profile)

    print("\n[✓] CatNet scan completed.\n")
