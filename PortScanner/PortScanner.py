from scapy.all import *
import random
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="Target IP address to scan", required=True)
parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan")
parser.add_argument("-s", "--start", help="Start of port range to scan" ,type=int, default=1)
parser.add_argument("-e", "--end", help="End of port range to scan", type=int, default=1024)
args = parser.parse_args()

target = args.target
targeted_port = args.ports
start_port = args.start
end_port = args.end

def syn_scan(target, port, retries=2, timeout=2):
    for attempt in range(retries + 1):
        sport = random.randint(1024, 65535)
        packet = IP(dst=target) / TCP(sport=sport, 
                                      dport=port, 
                                      flags="S",)

        response = sr1(packet, timeout=timeout, verbose=0)

        if response is None:
            if attempt == retries:
                return f"No response for port {port} after {retries} attempts, marking as filtered"
            continue

        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags
            if flags & 0x12 == 0x12:  # SYN-ACK
                rst = IP(dst=target) / TCP(sport=sport,
                                          dport=port, 
                                          flags="R",
                                          seq=response.ack)
                sr1(rst, timeout=timeout, verbose=0)
                return "OPEN"
            elif flags & 0x14 == 0x14:  # RST-ACK
                return "CLOSED"
        elif response.haslayer(ICMP):
            icmp = response.getlayer(ICMP)
            if icmp.type == 3:
                return f"FILTERED (ICMP type 3 code {icmp.code})"
    return "UNKNOWN"


if targeted_port:
    ports = [int(p.strip()) for p in targeted_port.split(",")]
    for port in ports:
        result = syn_scan(target, port)
        print(f"Port {port}: {result}")

for port in range(start_port, end_port):
    result = syn_scan(target, port)
    print(f"Port {port}: {result}")

