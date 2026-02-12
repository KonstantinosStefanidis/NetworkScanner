import argparse
from scanner.syn_scan import syn_scan


def run():
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

    if targeted_port:
        ports = [int(p.strip()) for p in targeted_port.split(",")]
        for port in ports:
            result = syn_scan(target, port)
            print(f"Port {port}: {result}")

    for port in range(start_port, end_port + 1):
        result = syn_scan(target, port)
        print(f"Port {port}: {result}")
