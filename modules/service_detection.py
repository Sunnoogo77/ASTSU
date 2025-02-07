from scapy.all import *
import socket
import platform
from nmap_vscan import vscan

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
    

# from nmap_vscan import vscan
# import sys,platform

# def scan_service(target,port):
#     return True

#     if platform.system() == 'Linux':
#         nmap = vscan.ServiceScan('/usr/share/astsu/service_probes')
#     elif platform.system() == 'Windows':
#         nmap = vscan.ServiceScan('C:\\Projetos\\Tools\\Network Tool\\service_probes')
#     try:
#         result = nmap.scan(str(target), int(port), 'tcp')
#     except Exception as e:
#         return e
#     service_name = str(result['match']['versioninfo']['cpename'])
    
#     service_name = service_name.replace('[','')
#     service_name = service_name.replace(']','')
#     service_name = service_name.replace("'","",2)

#     if not service_name:
#         service_name = 'Not found any service'
#     return service_name
