import argparse
from scanner.syn_scan import syn_scan


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Target IP address to scan", required=True)
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan", type=int)
    parser.add_argument("-s", "--start", help="Start of port range to scan" ,type=int)
    parser.add_argument("-e", "--end", help="End of port range to scan", type=int)
    args = parser.parse_args()

    target = args.target
    targeted_port = args.ports
    start_port = args.start
    end_port = args.end
    open_ports = []
    filtered_ports = []

    if targeted_port:
        #BUG: This doesnt work as intented, it only takes the first port and ignores the rest. 
        #Need to split the string by comma and convert each to int.
        ports = [int(p.strip()) for p in targeted_port.split(",")]
        for port in ports:
            result = syn_scan(target, port)
            if result == "OPEN":
                open_ports.append(port)
            if result == "FILTERED":
                filtered_ports.append(port)

        for port in range(start_port, end_port + 1):
            result = syn_scan(target, port)
            if result == "OPEN":
                open_ports.append(port)
            if result == "FILTERED":
                filtered_ports.append(port)

    print("Scan completed.")

    print(f"Open ports:{len(open_ports)}")
    for port in open_ports:
        print(f"Port {port} is OPEN")

    print(f"Filtered ports:{len(filtered_ports)}")
    for port in filtered_ports:
        print(f"Port {port} is FILTERED")
    

