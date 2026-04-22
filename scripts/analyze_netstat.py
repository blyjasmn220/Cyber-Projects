import re

SUSPICIOUS_PORTS = {
    4444: "Common Metasploit / reverse shell port",
    1337: "Leet / often used in CTF or malware samples",
    6666: "Sometimes used in backdoors",
    31337: "Elite / legacy hacking reference port",
    8081: "Alternative web service, sometimes abused"
}

def parse_netstat(file_path):
    connections = []

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            # Look for lines with "LISTENING" or connections
            match = re.search(r":(\d+)\s+.*\s+LISTENING", line)
            if match:
                port = int(match.group(1))
                connections.append(port)

    return connections


def analyze_ports(ports):
    print("\n🔍 Netstat Security Analysis Report\n")
    
    if not ports:
        print("No listening ports found or file format unexpected.")
        return

    for port in set(ports):
        if port in SUSPICIOUS_PORTS:
            print(f"🚨 Port {port} - SUSPICIOUS: {SUSPICIOUS_PORTS[port]}")
        else:
            print(f"✅ Port {port} - Normal/Unknown service")


if __name__ == "__main__":
    file_path = "logs/netstat.txt"
    ports = parse_netstat(file_path)
    analyze_ports(ports)

    print("SCRIPT IS RUNNING")