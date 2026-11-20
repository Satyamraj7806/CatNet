"""Fast, network-free checks for CatNet's rich report helpers."""

import xml.etree.ElementTree as ET

from catnet.stages.portscan import _parse_host
from catnet.stages.service_scan import _extract_services
from catnet.stages.classification import classify_host

XML = '''<host><status state="up"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<address addr="02:00:00:00:00:10" addrtype="mac" vendor="Example Vendor"/>
<hostnames><hostname name="test-host" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10">
<cpe>cpe:/a:openbsd:openssh:9.6</cpe></service></port></ports>
<os><osmatch name="Linux 5.X" accuracy="96"><osclass type="general purpose" vendor="Linux" osfamily="Linux"/></osmatch></os>
</host>'''


def main():
    host = _parse_host(ET.fromstring(XML))
    services = _extract_services(ET.fromstring(f"<nmaprun>{XML}</nmaprun>"))
    assert host["ports"][0]["port"] == 22
    assert host["ports"][0]["protocol"] == "TCP"
    assert host["mac_vendor"] == "Example Vendor"
    assert services[0]["product"] == "OpenSSH"
    classification = classify_host({"matches": host["os_matches"]}, services, "test-host", "Example Vendor")
    assert classification["label"] == "Likely Linux-based host"
    assert classification["confidence"] == "High"
    print("CatNet rich-output smoke checks passed.")


if __name__ == "__main__":
    main()
