import scapy.all as scapy

def scan(target, interface=None):
    try:
        os_ttl = {
            'Linux':[64],
            'Windows':[128, 255],
            'Unix/BSD':[255]
        }
        
        icmp_pkt = scapy.IP(dst=target, ttl=128) / scapy.ICMP()
        
        if interface:
            ans, uns = scapy.sr(icmp_pkt, retry=5, timeout=3, inter=1, verbose=0, iface=interface)
        else:
            ans, uns = scapy.sr(icmp_pkt, retry=5, timeout=3, inter=1, verbose=0)
        
        if len(ans) == 0:
            print(" ICMP bloqué. Possible firewall détecté !")
            return "Firewall détecté"
        
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
        
        #Fingerprinting TCP (envoie d'un paquet SYN sur un prt ouvert)
        tcp_pkt = scapy.IP(dst=target) / scapy.TCP(dport=80, flags='S')
        tcp_resp  = scapy.sr1(tcp_pkt, timeout=3, verbose=0)
        
        if tcp_resp and tcp_resp.haslayer(scapy.TCP):
            flags = tcp_resp.getlayer(scapy.TCP).sprintf('%flags%')
            if flags == 0x12: #SYNC-ACK reçu
                detected_os += " - (TCP stack analysé)"
            elif flags == 0x14: #RST-ACK reçu
                detected_os += " - (TCP stack detecté)"
        
        tcp_ack_pkt = scapy.IP(dst=target) / scapy.TCP(dport=80, flags='A')  # "A" = ACK
        ack_resp = scapy.sr1(tcp_ack_pkt, timeout=3, verbose=0)

        if ack_resp is None:
            print("⚠️  Aucun retour au paquet ACK. Un firewall filtre peut-être les connexions.")
            return detected_os + " - Firewall détecté"
            
        return detected_os
    
    except Exception as e:
        print("[-] Erreur lors de la détection de l'OS: ", e)
        return "OS Inconnu"