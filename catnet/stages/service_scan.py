import socket
COMMON_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
    }
    


def service_scan(ip, open_ports):
    print(f"[+] Starting service scan on {ip}")

    services= {}
    for port in open_ports:
        service = COMMON_SERVICES.get(port, "unknown")

        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            services[port] = service
            print(f"  [+] Port {port} --> ({service}) is open")
            s.close()
        except:
            pass

    return services

