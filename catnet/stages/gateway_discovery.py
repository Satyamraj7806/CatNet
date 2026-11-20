import subprocess
import platform
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_gateway(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_arg = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    
    command = ['ping', param, '1', timeout_arg, timeout_val, ip]
    
    try:
        output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if output.returncode == 0:
            return ip
    except Exception:
        pass
    return None

def main():
    base_ip = input("Enter the network prefix (e.g., 192.168 or 10.0): ").strip()
    start_vlan = int(input("Enter starting VLAN/octet number (e.g., 1): "))
    end_vlan = int(input("Enter ending VLAN/octet number (e.g., 255): "))
    
    print(f"\n[+] Scanning VLAN gateways ({base_ip}.[{start_vlan}-{end_vlan}].1) in parallel... Please wait.\n")
    
    start_time = time.time()
    active_vlans = []
    
    gateway_ips = [f"{base_ip}.{i}.1" for i in range(start_vlan, end_vlan + 1)]
    
    max_threads = 50
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_ip = {executor.submit(check_gateway, ip): ip for ip in gateway_ips}
        
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                parts = result.split('.')
                vlan_num = parts[2]
                print(f"[ACTIVE] Gateway responded: {result}  --> Subnet: {base_ip}.{vlan_num}.0/24")
                active_vlans.append(f"{base_ip}.{vlan_num}.0/24")
                
    elapsed = time.time() - start_time
    
    print(f"\n----------------------------------------------------")
    print(f"Scan Complete in {elapsed:.2f} seconds!")
    print("Active Subnets Found:")
    
    if active_vlans:
        for subnet in sorted(active_vlans, key=lambda x: int(x.split('.')[2])):
            print(f" - {subnet}")
    else:
        print(" - No active gateways found in this range.")

    print("\n[INFO] You can now use these subnets for further scanning in CatNet.")
    print("\n----------------------------------------------------\n")

if __name__ == "__main__":
    main()