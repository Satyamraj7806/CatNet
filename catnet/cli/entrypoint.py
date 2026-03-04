from catnet.orchestrator.orchestrator import run_pipeline
from catnet.core.profiles import scan_profiles
import socket


def detect_local_network():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    network = ".".join(local_ip.split(".")[:3]) + ".0/24"
    return network


def choose_profile():
    print("\nSelect Scan Depth:")
    print("1) Quick")
    print("2) Standard")
    print("3) Deep")

    choice = input("Choose option: ")

    if choice == "1":
        return scan_profiles["quick"]
    elif choice == "2":
        return scan_profiles["standard"]
    elif choice == "3":
        return scan_profiles["deep"]
    else:
        print("Invalid choice. Defaulting to Quick.")
        return scan_profiles["quick"]


def main():
    print("\nWelcome to CatNet Advanced Recon Framework\n")

    while True:
        print("1) Scan Single Device")
        print("2) Scan Local Network")
        print("3) Exit")

        choice = input("Choose option: ")

        if choice == "1":
            target = input("Enter IP address: ")
            profile = choose_profile()
            run_pipeline(target, profile)

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
    main()