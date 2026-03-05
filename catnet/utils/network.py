import socket 

def detect_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try :
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]

    finally:
        sock.close()

    return ip


def get_local_network():

    ip = detect_local_ip()

    parts = ip.split(".")
    network  = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return network