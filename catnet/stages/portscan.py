import subprocess
import xml.etree.ElementTree as ET

def port_scan(host, output_base, profile):
    """
    Runs a TCP SYN scan (-sS) against a discovered host
    and returns structured port scan results.
    """

    ip = host["target"]
    xml_file = f"{output_base}_{ip}.xml"

    print(f"[+] Starting port scan on {ip}({profile['name']})")

    command = ["nmap"] + profile["nmap_args"] + ["-oX", xml_file, ip]

    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode != 0:
        return {
            "target": ip,
            "ports": [],
            "error": "Nmap execution failed",
            "stage": "port_scan"
        }

    # --- XML parsing ---
    try:
        tree = ET.parse(xml_file)
    except FileNotFoundError:
        return {
            "target": ip,
            "ports": [],
            "error": "Port scan XML not found",
            "stage": "port_scan"
        }
    except ET.ParseError:
        return {
            "target": ip,
            "ports": [],
            "error": "Invalid XML format",
            "stage": "port_scan"
        }

    root = tree.getroot()
    open_ports = []

    # --- Extract open ports ---
    host_elem = root.find("host")
    if host_elem is not None:
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state = port_elem.find("state")

                if state is not None and state.get("state") == "open":
                    open_ports.append({
                        "port": port_elem.get("portid"),
                        "protocol": port_elem.get("protocol")
                    })

    # --- Final structured output ---
    return {
        "target": ip,
        "ports": open_ports,
        "error": None,
        "stage": "port_scan"
    }