import argparse
from math import e
import threading
import time
import ipaddress
from tqdm import tqdm
from scanner.syn_scan import syn_scan
from concurrent.futures import ThreadPoolExecutor
from scanner.banner_grab import grab_banner


def run():
    threading.excepthook = scapy_thread_error_filter
    start_time = time.time()

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

    #Error checks
    if bool(start_port) != bool(end_port):
        print("Error: --start and --end must be used together.")
        return
    
    try:
        ipaddress.ip_address(target)
    except ValueError:
        print(f"Error: '{target}' is not a valid IP address.")
        return
    
    if start_port and end_port:
        if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
            print("Error: Ports must be between 1 and 65535.")
            return
        if start_port > end_port:
            print("Error: Start port must be less than or equal to end port.")
            return

    #Scanning starts here
    if targeted_port:
        ports = [int(p.strip(",")) for p in targeted_port]
        if any(not (1 <= p <= 65535) for p in ports):
            print("Error: Ports must be between 1 and 65535.")
            return
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(tqdm(executor.map(lambda port: scan_and_store(target, port), ports),
                    total=len(ports), desc="Scanning"))
        for port, result in results:
            if result == "OPEN":
                open_ports.append(port)
            elif "FILTERED" in result:
                filtered_ports.append(port)

    if start_port and end_port:
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(tqdm(executor.map(lambda port: scan_and_store(target, port), range(start_port, end_port + 1)),
                               total=end_port - start_port + 1, desc="Scanning"))
        for port, result in results:
            if result == "OPEN":
                open_ports.append(port)
            elif "FILTERED" in result:
                filtered_ports.append(port)

    #Outputs
    print(f"Open ports:{len(open_ports)}")
    for port in open_ports:
        banner = grab_banner(target, port)
        if banner:
            print(f"Port {port} is OPEN - Banner: {banner}")
        else:
            print(f"Port {port} is OPEN")
        
    print(f"Filtered ports:{len(filtered_ports)}")
    for port in filtered_ports:
        print(f"Port {port} is FILTERED")

    elapsed = time.time() - start_time
    print(f"Scan completed in {elapsed:.2f} seconds.")

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
