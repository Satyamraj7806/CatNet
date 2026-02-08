import subprocess

target = input("enter the IP: ")
output_base = input("enter the output base name (without extension): ")

command = ["nmap", "-sn", "-oX", f"{output_base}.xml", target]

subprocess.run(command)