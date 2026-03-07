import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from catnet.stages.discovery import run_discovery
from catnet.stages.portscan import port_scan
from catnet.stages.service_scan import service_scan


def run_pipeline(target, profile):
    """
    CatNet Scanning Pipeline

    Stage 1 - Host Discovery
    Stage 2 - Port Scanning (parallel)
    Stage 3 - Service Detection
    """

    output_base = f"catnet_scan_{int(time.time())}"

    # =========================
    # STAGE 1 - HOST DISCOVERY
    # =========================

    print("\n[STAGE 1] Host Discovery")
    print("------------------------")

    discovery_result = run_discovery(output_base, target)

    if discovery_result["error"]:
        print(f"[ERROR] {discovery_result['error']}")
        return

    hosts = discovery_result["hosts"]

    if not hosts:
        print("[INFO] No live hosts found.")
        return

    print(f"[INFO] {len(hosts)} host(s) discovered:\n")

    for host in hosts:
        print(f"  [+] Host up: {host['target']}")

    # =========================
    # STAGE 2 - PORT SCANNING
    # =========================

    print("\n[STAGE 2] Port Scanning")
    print("------------------------")

    port_results = {}

    with ThreadPoolExecutor(max_workers=5) as executor:

        futures = {
            executor.submit(port_scan, host, output_base, profile): host
            for host in hosts
        }

        for future in as_completed(futures):

            result = future.result()

            if result["error"]:
                print(f"[ERROR] {result['error']}")
                continue

            ip = result["target"]
            port_results[ip] = result

            print(f"\nResults for {ip}")

            if not result["ports"]:
                print("  No open ports")

            else:
                for port in result["ports"]:
                    print(f"  {port['port']}/{port['protocol']}")

    # =========================
    # STAGE 3 - SERVICE SCAN
    # =========================
    print("DEBUG: entering stage 3")

    print("\n[STAGE 3] Service Detection")
    print("----------------------------")

    for host in hosts:

        ip = host["target"]

        result = port_results.get(ip)

        if not result:
            print(f"\n{ip} → No port scan results")
            continue

        open_ports = [int(p["port"]) for p in result.get("ports", [])]

        if not open_ports:
            print(f"\n{ip} → No open ports")
            continue

        print(f"\nScanning services on {ip}")

        services = service_scan(ip, open_ports)

        if not services:
            print("  No services identified")

        else:
            for port, service in services.items():
                print(f"  Port {port} --> ({service})")

    print("\n[✓] Scan completed.\n")