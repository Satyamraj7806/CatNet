

scan_profiles = {

    "quick": {
        "name": "Quick Port Scan",
        "nmap_args": ["-sS", "-T4", "--top-ports", "100", "--reason"],
        "os_detection": False,
        "protocol_enumeration": False,
        "description": "Scans the 100 most common TCP ports.",
    },
    "standard": {
        "name": "Standard Port Scan",
        "nmap_args": [
            "-sS", "-sV", "--version-light", "-T4",
            "--top-ports", "1000", "--reason",
        ],
        "os_detection": False,
        "protocol_enumeration": True,
        "description": "Scans 1,000 common TCP ports and lightly probes services.",
    },
    "all_tcp": {
        "name": "All TCP Ports",
        "nmap_args": ["-sS", "-T4", "-p-", "--reason"],
        "os_detection": False,
        "protocol_enumeration": False,
        "description": "Scans TCP ports 1–65535; this may take longer.",
    },
    "detailed": {
        "name": "Detailed Service and OS Scan",
        "nmap_args": ["-sS", "-sV", "-O", "-T4", "-p-", "--reason"],
        "os_detection": True,
        "protocol_enumeration": True,
        "description": "Scans all TCP ports and requests service/version and OS detection.",
    },
    "low_timing": {
        "name": "Stealth Scan",
        "nmap_args": ["-sT", "-T2", "--top-ports", "100", "--reason"],
        "os_detection": False,
        "protocol_enumeration": False,
        "description": "Scans 100 common TCP ports using slower timing; it may still be detected.",
    },
}
