from scapy.all import *
import random

def syn_scan(target, port, retries=2, timeout=2):
    for attempt in range(retries + 1):
        sport = random.randint(1024, 65535)
        packet = IP(dst=target) / TCP(sport=sport, 
                                      dport=port, 
                                      flags="S",)

        response = sr1(packet, timeout=timeout, verbose=0)

        if response is None:
            if attempt == retries:
                return "FILTERED"
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
