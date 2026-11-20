"""Task-oriented command-line menu for CatNet."""

from __future__ import annotations

import ipaddress
import re
import sys
import time
from typing import Optional

from catnet.core.profiles import scan_profiles
from catnet.orchestrator.orchestrator import run_pipeline
from catnet.stages.discovery import run_discovery
from catnet.utils.network import get_local_network


def detect_local_network() -> str:
    """Return the current local network in CIDR form, if available."""
    network = get_local_network()
    if not network:
        raise RuntimeError("Could not determine the local network automatically.")
    return str(network)


def _valid_target(target: str) -> bool:
    """Accept an IP address, CIDR network, or ordinary DNS hostname."""
    if not target or target.startswith("-") or any(ch.isspace() for ch in target):
        return False
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        # Permit a hostname, but not Nmap option-like strings or shell syntax.
        if len(target) > 253 or "/" in target or "\\" in target:
            return False
        labels = target.rstrip(".").split(".")
        return all(
            1 <= len(label) <= 63
            and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        )


def ask_target() -> Optional[str]:
    """Ask for an IP/CIDR/hostname; Enter uses the detected local network."""
    try:
        default_target = detect_local_network()
    except Exception:
        default_target = ""

    if default_target:
        raw = input(f"Target IP/CIDR/hostname [Enter = {default_target}]: ").strip()
        target = raw or default_target
    else:
        target = input("Target IP/CIDR/hostname: ").strip()

    if not _valid_target(target):
        print("[ERROR] Invalid target. Enter an IP, CIDR range, or hostname.\n")
        return None
    return target


def _print_banner() -> None:
    print(r"""
  ____      _   _   _      _
 / ___|__ _| |_| \ | | ___| |_
| |   / _` | __|  \| |/ _ \ __|
| |__| (_| | |_| |\  |  __/ |_
 \____\__,_|\__|_| \_|\___|\__|
    """)
    print("Network reconnaissance for systems you are authorized to assess.\n")


def live_host_discovery() -> None:
    """Run only Nmap host discovery (-sn) and print responding hosts."""
    target = ask_target()
    if not target:
        return

    output_base = f"catnet_live_discovery_{int(time.time())}"
    print("\n[HOST DISCOVERY]")
    print(f"Target: {target}\n")
    started = time.monotonic()
    result = run_discovery(output_base, target)
    elapsed = time.monotonic() - started

    if result.get("error"):
        print(f"[ERROR] {result['error']}\n")
        return

    hosts = result.get("hosts", [])
    print("─" * 64)
    print(f"LIVE HOSTS: {len(hosts)}")
    print("─" * 64)
    if hosts:
        for index, host in enumerate(hosts, 1):
            print(f"{index:>3}. {host.get('target', 'Unknown')}")
    else:
        print("No hosts responded to the discovery methods used.")
        print("Note: silence does not prove a device is offline; discovery traffic may be filtered.")
    print(f"\nElapsed: {elapsed:.1f} seconds")
    print(f"Raw XML: {output_base}.xml\n")


def _run_profile(profile_key: str) -> None:
    target = ask_target()
    if not target:
        return
    profile = scan_profiles[profile_key]
    print(f"\n[+] {profile['name']}")
    print(f"    {profile.get('description', '')}\n")
    run_pipeline(target, profile)


def port_scan_menu() -> None:
    """Select scan scope separately from the overall feature menu."""
    while True:
        print("\nPORT SCANNING")
        print("1) Quick port scan (top 100 TCP ports)")
        print("2) Standard port scan (top 1,000 TCP ports + light service probes)")
        print("3) All TCP ports (1–65535)")
        print("4) Back to main menu")
        choice = input("Choose option: ").strip()
        if choice == "1":
            _run_profile("quick")
        elif choice == "2":
            _run_profile("standard")
        elif choice == "3":
            _run_profile("all_tcp")
        elif choice == "4":
            return
        else:
            print("Invalid option. Choose 1–4.")


def custom_scan() -> None:
    """Build a constrained custom TCP scan without accepting arbitrary flags."""
    target = ask_target()
    if not target:
        return

    ports = input("Ports (e.g. 22,80,443 or 1-1024) [default 1-1000]: ").strip() or "1-1000"
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", ports):
        print("[ERROR] Invalid port format. Use e.g. 22,80,443 or 1-1024.\n")
        return
    for item in ports.split(","):
        bounds = item.split("-")
        try:
            start = int(bounds[0])
            end = int(bounds[-1])
        except ValueError:
            print("[ERROR] Invalid port number.\n")
            return
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            print("[ERROR] Ports must be in the range 1–65535 and range starts must not exceed ends.\n")
            return

    print("\nScan method:")
    print("1) SYN scan (-sS; normally requires elevated privileges)")
    print("2) TCP connect scan (-sT)")
    method = input("Choose method [1]: ").strip() or "1"
    if method not in {"1", "2"}:
        print("Invalid method.\n")
        return

    print("\nTiming:")
    print("2) Slower timing")
    print("3) Normal timing")
    print("4) Faster timing")
    timing = input("Choose timing [3]: ").strip() or "3"
    if timing not in {"2", "3", "4"}:
        print("Invalid timing.\n")
        return

    service_detection = input("Attempt service/version detection? [y/N]: ").strip().lower() in {"y", "yes"}
    os_detection = input("Attempt OS detection? [y/N]: ").strip().lower() in {"y", "yes"}

    args = ["-sS" if method == "1" else "-sT", f"-T{timing}", "-p", ports, "--reason"]
    if service_detection:
        args.append("-sV")
    if os_detection:
        args.append("-O")

    profile = {
        "name": "Custom Scan",
        "nmap_args": args,
        "os_detection": os_detection,
        "protocol_enumeration": service_detection,
        "description": f"Custom TCP ports: {ports}; timing T{timing}.",
    }
    print("\n[!] Use custom scans only on targets you are authorized to assess.")
    print(f"[+] Arguments: {' '.join(args)}\n")
    run_pipeline(target, profile)


def gateway_discovery() -> None:
    """Load the standalone user-owned gateway scanner only when selected."""
    try:
        from catnet.stages.gateway_discovery import main as gateway_main
    except ImportError as exc:
        print(f"[ERROR] Could not load gateway discovery: {exc}")
        print("Check that catnet/stages/gateway_discovery.py defines main().\n")
        return
    gateway_main()


def main() -> None:
    _print_banner()
    while True:
        print("MAIN MENU")
        print("1) Gateway / VLAN Discovery")
        print("2) Live Host Discovery ")
        print("3) Port Scanning ")
        print("4) Detailed Service & OS Scan")
        print("5) Stealth Scan")
        print("6) Custom Scan")
        print("7) Exit")
        choice = input("Choose option: ").strip()

        try:
            if choice == "1":
                gateway_discovery()
            elif choice == "2":
                live_host_discovery()
            elif choice == "3":
                port_scan_menu()
            elif choice == "4":
                _run_profile("detailed")
            elif choice == "5":
                print("\n[!] Stealth scan does not make a scan completely undetectable. Use only with authorization.\n")
                _run_profile("low_timing")
            elif choice == "6":
                custom_scan()
            elif choice == "7":
                print("Exiting CatNet.")
                return
            else:
                print("Invalid option. Choose 1–7.\n")
        except KeyboardInterrupt:
            print("\n[!] Current operation interrupted by user. Returning to menu.\n")
        except Exception as exc:
            print(f"[ERROR] {exc}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting CatNet.")
        sys.exit(130)
