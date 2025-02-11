from scapy.all import *
import socket

def scan_service(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, port))

        if result == 0:
            sock.sendall(b"HELLO\r\n")
            response = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            if response:
                return f"[BANNIÈRE] {response}"

    except Exception as e:
        return f"[ERREUR] {e}"