import time

from catnet.stages.discovery import run_discovery
from catnet.stages.portscan import port_scan


def run_pipeline(target):
    """
    Controls the full CatNet scanning pipeline:
    1. Host discovery
    2. Port scanning
    3. Structured output display
    """

    # Generate a unique output base for this run
    output_base = f"catnet_scan_{int(time.time())}"

    print("\n[STAGE 1] Host Discovery")
    print("------------------------")

    discovery_result = run_discovery(output_base, target)

    # --- Handle discovery error ---
    if discovery_result["error"]:
        print(f"[ERROR] {discovery_result['error']}")
        return

    hosts = discovery_result["hosts"]
    total_hosts = len(hosts)

    if total_hosts == 0:
        print("[INFO] No live hosts found.")
        return

    print(f"[INFO] {total_hosts} host(s) discovered:\n")

    for host in hosts:
        print(f"  [+] Host up: {host['target']}")

    print("\n[STAGE 2] Port Scanning")
    print("------------------------")

    for index, host in enumerate(hosts, start=1):
        print(f"\n[{index}/{total_hosts}] Scanning {host['target']}...")

        scan_result = port_scan(host, output_base)

        if scan_result["error"]:
            print(f"  [ERROR] {scan_result['error']}")
            continue

        ports = scan_result["ports"]

        if not ports:
            print("  No open ports found.")
        else:
            print("  Open ports:")
            for port in ports:
                print(f"    - {port['port']}/{port['protocol']}")

    print("\n[✓] Scan completed.\n")