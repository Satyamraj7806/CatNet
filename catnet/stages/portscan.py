import subprocess
import xml.etree.ElementTree as ET


def port_scan(host, output_base):
    print("Starting port scanning")

    ip = host["target"]
    xml_file = f"{output_base}_{ip}.xml"

    command = ["nmap", "-sS", "-oX", xml_file, ip]
    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode != 0:
        return {
            "target": ip,
            "ports": [],
            "error": "Nmap failed",
            "stage": "port_scan"
        }

    try:
        tree = ET.parse(xml_file)
    except FileNotFoundError:
        return {
            "target": ip,
            "ports": [],
            "error": "XML missing",
            "stage": "port_scan"
        }

    root = tree.getroot()
    open_ports = []

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
    if __name__ == "__main__":
        test_host = {"target": "127.0.0.1"}
        result = port_scan(test_host, "scan_output")
        print(result)
    return {
        "target": ip,
        "ports": open_ports,
        "error": None,
        "stage": "port_scan"
    }

    