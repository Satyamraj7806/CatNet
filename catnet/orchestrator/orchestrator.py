import time

from catnet.stages.discovery import run_discovery
from catnet.stages.portscan import port_scan
from catnet.core.profiles import scan_profiles
from catnet.utils.network import get_local_network
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_pipeline(target, profile):
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

    # --- Run port scans in parallel ---

    with ThreadPoolExecutor(max_workers=5) as executor:

        futures = []
        for host in hosts:
            # Change this line in orchestrator.py
            future = executor.submit(port_scan, host, output_base, profile)
            futures.append(future)

        for future in as_completed(futures):
            result = future.result()
            
            if result["error"]:
                print(f"[ERROR] {result['error']}")
                continue

            print(f"\nResults for {result['target']}")

            if not result["ports"]:
                print("  No open ports")

            else:
                for port in result["ports"]:
                    print(f"  {port['port']}/{port['protocol']}")

    print("\n[✓] Scan completed.\n")