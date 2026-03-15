
# NetworkScanner

A multithreaded TCP SYN port scanner built in Python using Scapy. Designed to explore low-level packet crafting and TCP handshake behavior.

## Features
- TCP SYN scanning
- Multithreading
- Banner grabbing on open ports
- Progress bar
- Scan timer

## Requirements
- Requires Python 3.8+
- Scapy
- tqdm
- Npcap(Windows only) - https://npcap.com
- libpcap (Linux) — usually pre-installed, or `sudo apt install libpcap-dev`


## Installation
```bash
pip install netscan-ks
```
> **Note:** On Linux and macOS, run with `sudo` as raw sockets require root privileges.

## Usage
Use -h for help, but here is a short tutorial.
-t is the target (Needs to be a valid IP address)
-p is specific ports.
-s and -e are start and end of a range of ports.
Scan specific ports:
```bash
netscan -t 192.168.1.1 -p 80 443 22
```
Scan a port range:
```bash
netscan -t 192.168.1.1 -s 1 -e 1024
```

## How It Works
It sends TCP SYN packets to each target port and analyzes the response. A SYN-ACK response indicates the port is open, an RST response indicates it is closed, and no response indicates it is filtered. Unlike a full TCP connect scan, the connection is never completed, making it faster and less likely to appear in application logs.


## Legal Notice
This tool is intended for educational purposes and authorized security testing only. Do not use this scanner against networks or systems you do not own or have explicit permission to test. Unauthorized scanning may violate local laws and regulations. The author assumes no liability for misuse of this tool.
