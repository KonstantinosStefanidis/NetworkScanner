import argparse
import sys
import os
import threading
from scanner.syn_scan import syn_scan
from concurrent.futures import ThreadPoolExecutor


def run():
    threading.excepthook = scapy_thread_error_filter

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Target IP address to scan", required=True)
    parser.add_argument("-p", "--ports", help="Specific ports to scan", nargs="+")
    parser.add_argument("-s", "--start", help="Start of port range to scan" ,type=int)
    parser.add_argument("-e", "--end", help="End of port range to scan", type=int)
    args = parser.parse_args()

    target = args.target
    targeted_port = args.ports
    start_port = args.start
    end_port = args.end
    open_ports = []
    filtered_ports = []

    print(f"Starting scan on {target}...")

    if targeted_port:
        ports = [int(p.strip(",")) for p in targeted_port]
        for port in ports:
            result = syn_scan(target, port)
            if result == "OPEN":
                open_ports.append(port)
            if result == "FILTERED":
                filtered_ports.append(port)

    if start_port and end_port:
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(lambda port: scan_and_store(target, port), range(start_port, end_port + 1))
        for port, result in results:
            if result == "OPEN":
                open_ports.append(port)
            elif result == "FILTERED":
                filtered_ports.append(port)

    print("Scan completed.")

    print(f"Open ports:{len(open_ports)}")
    for port in open_ports:
        print(f"Port {port} is OPEN")

    print(f"Filtered ports:{len(filtered_ports)}")
    for port in filtered_ports:
        print(f"Port {port} is FILTERED")

def scan_and_store(target, port):
    result = syn_scan(target, port)
    return (port, result)

# Scapy's sr1() spawns internal threads for packet sending/receiving.
# When running my own scans with ThreadPoolExecutor, these internal threads occasionally fail with OSError errno 9 (Bad file descriptor)
# and errno 22 (Invalid argument) during cleanup. These are known Scapy pipe errors on Windows and do not affect scan results.
# threading.excepthook is used to suppress these specific errors only. To clarify, the errors do occur on every scan, they are just not visible to the user.
def scapy_thread_error_filter(args):
    if isinstance(args.exc_value, OSError) and args.exc_value.errno in (9, 22):
        return
    threading.__excepthook__(args)
