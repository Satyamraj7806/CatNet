from catnet.orchestrator.orchestrator import run_pipeline
from catnet.core.profiles import scan_profiles
from catnet.utils.network import get_local_network
import socket
import sys


def detect_local_network():
    network = get_local_network()
    return network


def choose_profile():
    print("\nSelect Scan Depth:")
    print("1) Quick")
    print("2) Standard")
    print("3) Deep")
    print("4) Stealth")

    choice = input("Choose option: ")

    if choice == "1":
        return scan_profiles["quick"]
    elif choice == "2":
        return scan_profiles["standard"]
    elif choice == "3":
        print("\n[!] Deep Scan selected. This will perform a comprehensive scan and may take significantly longer.\n")
        return scan_profiles["deep"]
    elif choice == "4":
        print("\n[!] Stealth Scan selected. This may take longer but is less likely to be detected ;)\n")         
        return scan_profiles["stealth"]
    else:
        print("Invalid choice. Defaulting to Quick.")
        return scan_profiles["quick"]


def main():
    print(r"""
  ____      _   _   _      _   
 / ___|__ _| |_| \ | | ___| |_ 
| |   / _` | __|  \| |/ _ \ __|
| |__| (_| | |_| |\  |  __/ |_ 
 \____\__,_|\__|_| \_|\___|\__|
    """)
    while True:
        print("1) Scan Single Device")
        print("2) Scan Local Network")
        print("3) Exit")

        choice = input("Choose option: ")

        if choice == "1":
            target = input("Enter IP address: ")
            profile = choose_profile()
            run_pipeline(target,profile)

        elif choice == "2":
            network = detect_local_network()
            print(f"\nDetected Local Network: {network}")
            profile = choose_profile()
            run_pipeline(network, profile)

        elif choice == "3":
            print("Exiting CatNet.")
            break

        else:
            print("Invalid option.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        print("Exiting CatNet.")
        sys.exit(0)