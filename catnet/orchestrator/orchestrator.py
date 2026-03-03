from catnet.stages.discovery import run_discovery
from catnet.stages.portscan import port_scan
import os
import time


def run_pipeline(target):
    output_base = f"scan_{int(time.time())}"

    discovery_result = run_discovery(output_base, target)

    if discovery_result["error"]:
        print(discovery_result["error"])
        return

    for host in discovery_result["hosts"]:
        port_scan(host, output_base)