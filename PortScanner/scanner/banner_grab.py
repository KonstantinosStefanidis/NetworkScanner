import socket

def grab_banner(target, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return None