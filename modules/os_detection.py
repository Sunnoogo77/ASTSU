# import scapy.all as scapy

# def scan(target):
#     os_ttl = {
#         'Linux': [64],
#         'Windows': [128, 255],
#         'Unix': [255]
#     }
    
#     pkt = scapy.IP(dst=target)/scapy.ICMP()
#     response = scapy.sr1(pkt, timeout=3, verbose=0)

#     if response:
#         target_ttl = response.ttl
#         for os_name, ttl_values in os_ttl.items():
#             if target_ttl in ttl_values:
#                 return os_name
#     return "OS Inconnu"

from scapy.all import *

def scan(target, interface=None):
    try:
        os_ttl = {
            'Linux':[64],
            'Windows':[128, 255],
            'Unix/BSD':[255]
        }
        
        icmp_pkt = scapy.IP(dst=target, ttl=128) / scapy.ICMP()
        
        if interface:
            ans, uns = sr(icmp_pkt, retry=5, timeout=3, inter=1, verbose=0, iface=interface)
        else:
            ans, uns = sr(icmp_pkt, retry=5, timeout=3, inter=1, verbose=0)
        
        try:
            target_ttl = ans[0][1].ttl
        except:
            print("[-] Hôte injoignable via ICMP")
            return "OS Inconnu"
        
        #Analyse du TTL
        detected_os = "Os Inconnu"
        for os_name, ttl_values in os_ttl.items():
            if target_ttl in ttl_values:
                detected_os = os_name
                break 
        
        #Fing