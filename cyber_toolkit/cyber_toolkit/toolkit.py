#PORT SCANNER 
import socket
target = input("Enter the target IP address: ")
print(f"Scanning [target].../n")
for port in range(1, 1025):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    result = s.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} is open")
    s.close()

    #THIS CHECKS PORTS THAT ARE OPEN 
    #INSTALL DEPENDENCY

from scapy.all import ARP, Ether, srp
target_ip = "192.168.1.1/24"

arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp
result = srp(packet, timeout=2, verbose=0)[0]

print("Device on network: /n")
for sent, received in result:
    print(f"IP: {received.psrc} MAC: {received.hwsrc}")

    #BANNER GRABBER
    import socket 
    target = input("Enter the target IP address: ")
    port = int(input("Enter the target port: "))

    s = socket.socket()
    s.connect((target, port))
    banner = s.recv(1024)

    print(f"Banner: {banner.decode().strip()}") 

    s.close()

    #GRABS IDENTIFYING INFO FROM A SERVICE 
    #SIMPLE LOG ANALYZER

    file = input("Enter the log file: ")
with open(file, "r") as f:
    logs = f.readlines()

failed = [line for line in logs if "failed" in line.lower()]
print(f"\nFailed attempts: {len(failed)}\n")

for line in failed[:10]:
    print(line.strip()) 

#FINDS SUSPICIOUS ACTIVITY IN LOGS
#COMBINE ALL TOOLS INTO ONE SCRIPT

print("""Port Scanner, Network Scanner, Banner Grabber, Log Analyzer""" )

choice = input("Select option: ")

#USE IPCONFIG FIND YOUR IP ADDRESS 
#LOOK FOR LINE IPv4 ADDRESS. THIS IS YOUR IP ADDRESS.