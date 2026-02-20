import subprocess
import xml.etree.ElementTree as ET



def run_discovery(output_base, target):
    xml_file = f"{output_base}.xml"
    command = ["nmap", "-sn", "-oX", xml_file, target]

    result = subprocess.run(command, stdout=subprocess.DEVNULL)

    if result.returncode != 0:
        return {
            "target": target,
            "hosts": [],
            "error": "Nmap failed"
        }

    try:
        tree = ET.parse(xml_file)
    except FileNotFoundError:
        return {
            "target": target,
            "hosts": [],
            "error": "XML missing"
        }

    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        address = host.find("address")

        if status is None or address is None:
            continue

        if status.get("state") == "up":
            hosts.append({
                "target": address.get("addr"),
                "stage": "discovery"
            })

    return {
        "target": target,
        "hosts": hosts,
        "error": None
    }
