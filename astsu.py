#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os,sys,argparse,textwrap,ipaddress,logging
import scapy.all as scapy
import socket
from ctypes import *
from time import sleep
from threading import Thread, Semaphore
from modules import service_detection,os_detection
from progress.bar import ChargingBar 
# from progress.bar import ChargingBar
# from colorama import Foreimport rpycolorlors
# old_print = printprint = rpycolors.Consolo().print


# Configuration des logs
logging.basicConfig(
    format='[%(levelname)s] %(message)s',
    level=logging.INFO
)

# logging.getLogger("scapy.runtime").setlevel(logging.ERROR)

clear = lambda:os.system('cls' if os.name == 'nt' else 'clear')

__version__ = "v1.1.4"

class Scanner:
    def __init__(self, target=None, my_ip=None, protocol=None, timeout=5, interface=None):
        self.target = target
        self.my_ip = my_ip
        self.protocol = protocol
        self.timeout = args.timeout if args.timeout else 5
        self.interface = args.interface if args.interface else None

        
    def port_scan(self, stealth=None, port=80):
        protocol = self.protocol if self.protocol else "TCP"
        
        if stealth:
            pkt = scapy.IP(dst=self.target) / scapy.TCP(dport=port, flags="S")
            scan = scapy.sr1(pkt, timeout=self.timeout, verbose=0) 
            
            
            if scan is None:
                return {port: 'Filtered'}
            
            elif scan.haslayer(scapy.TCP):
                if scan.getlayer(scapy.TCP).flags == 0x12: # 0x12 SYN+ACk
                    pkt = scapy.IP(dst=self.target) / scapy.TCP(dport = port, flags="R")
                    send_rst = scapy.sr(pkt, timeout=self.timeout, verbose=0)
                    return {port: 'Open'}
                
                elif scan.getlayer(scapy.TCP).flags == 0x14:
                    return {port: 'Closed'}
                
            elif scan.getlayer(scapy.ICMP):
                if scan.getlayer(scapy.ICMP).type == 3 and int(scan.getlayer(scapy.ICMP).code in [1,2,3,9,10,13]):
                    return {port: 'Filtered'}
                
        else:
            if protocol == "TCP":
                pkt = scapy.IP(dst=self.target)/scapy.TCP(dport=port, flags="S")
                scan = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
                
                if scan == None:
                    return {port: 'Filtered'}
                elif scan.haslayer(scapy.TCP):
                    if scan.getlayer(scapy.TCP).flags == 0x12: #0x12 Syn+Ack
                        pkt = scapy.IP(dst=self.target)/scapy.TCP(dport=port, flags="AR")
                        send_rst = scapy.sr(pkt, timeout=self.timeout, verbose=0)
                        return {port: 'Open'}
                    elif scan.getlayer(scapy.TCP).flags == 0x14:
                        return {port: 'Closed'}
                
            elif protocol == "UDP":
                pkt = scapy.IP(dst=self.target)/scapy.UDP(dport=port)
                scan = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
                
                if scan ==  None:
                    return {port: 'Open/Filtered'}
                elif scan.haslayer(scapy.UDP):
                    return {port: 'Closed'}
                elif scan.haslayer(scapy.ICMP):
                    if int(scan.getlayer(scapy.ICMP).type) == 3 and int(scan.getlayer(scapy.ICMP).code) == 3:
                        return {port: 'Closed'}
                
    def handle_port_response(self, ports_saved, response, port):
        open_port = ports_saved['open']
        filtered_ports = ports_saved['filtered']
        open_or_filtered = ports_saved['open/filtered']
        closed_ports = ports_saved['closed']
        
        if response[port] == 'Closed':
            print(f"[CLOSED]      ------> Port {port}")
            closed_ports.append(port)
        elif response[port] == 'Open':
            print(f"[OPEN]        ------> Port {port}")
            open_port.append(port)
        elif response[port] == 'Filtered':
            print(f"[FILTERED]     -----> Port {port}")
            filtered_ports.append(port)
        elif response[port] == 'Open/filtered':
            print(f"[OPEN/FILTERED]  --> Port {port}")
            open_or_filtered.append(port)
        else:
            pass
        
        return open_port, filtered_ports, open_or_filtered, closed_ports
    
    def common_scan(self, stealth=None, sv=None):
        protocol = self.protocol if self.protocol else "TCP"
        
        ports = [21, 22, 80, 443, 3306, 14147, 2121, 8080, 8000]
        open_ports = []
        filtered_ports = []
        open_or_filtered_ports = []
        closed_ports = []
        
        results_for_file = []
        
        if stealth:
            print("\n\n\tDémarrage - Scan furtif des ports --> TCP <--\n\n")
        else :
            if protocol == "TCP":
                print("\n\n\tDémarrage - Analyse des port --> TCP <--\n\n")
            elif protocol == "UDP":
                print("\n\n\tDémarrage - Scan du port --> UDP <-- \n\n")
            else:
                pass
            
        for port in ports:
            scan = self.port_scan(stealth=stealth, port=port)
            
            if scan:
                ports_saved = {
                    "open": open_ports,
                    "filtered":filtered_ports,
                    "open/filtered": open_or_filtered_ports,
                    "closed": closed_ports
                }
                open_ports, filtered_ports, open_or_filtered_ports, closed_ports = self.handle_port_response(
                    ports_saved=ports_saved, response=scan, port=port
                )
                
                    
                #Ajout des resultats formaté dans le fichier de sortie
                for status, ports_list in[
                    ("Open", open_ports), 
                    ("Filtered", filtered_ports), 
                    ("Open/Filtered", open_or_filtered_ports),
                    ("Closed", closed_ports)
                ]:
                    for port in ports_list:
                        results_for_file.append(f"Port: {port} - {status}")

        
        total = len(open_ports) + len(filtered_ports) + len(open_or_filtered_ports) + len(closed_ports)
        print(f"\n\t ✅ Scan terminé :{total} ports analysés dont : ")
        print(f"\t\t{len(open_ports)} - Open")
        print(f"\t\t{len(closed_ports)} - Closed\n")
        
            
        return results_for_file
    
    def range_scan(self, start, end=None, stealth=None, sv=None):
        
        open_ports = []
        filtered_ports = []
        open_or_filtered_ports = []
        protocol = self.protocol if self.protocol else "TCP"
        
        if protocol == "TCP" and stealth:
            logging.info("\n\tDémarrage - Analyse furtive des ports TCP\n")
        elif protocol == "TCP" and not stealth:
            logging.info("\n\tDémarrage - Analyse du port de connexion TCP\n")
        elif protocol == "UDP":
            logging.info("\n\tDémarrage - Scan du port UDP\\n")
        else:
            pass
            
        if end:
            ports = range(start, end + 1)
        else:
            ports = [start]

        for port in ports:
            scan = self.port_scan(port=port, stealth=stealth)

            if scan:
                ports_saved = {
                    "open": open_ports,
                    "filtered": filtered_ports,
                    "open/filtered": open_or_filtered_ports
                }

                open_ports, filtered_ports, open_or_filtered_ports = self.handle_port_response(
                    ports_saved=ports_saved, response=scan, port=port
                )

        total = len(open_ports) + len(filtered_ports) + len(open_or_filtered_ports)
        logging.info(f"Scan terminé : {total} ports analysés.")

        for port in open_ports:
            logging.info(f"Port: {port} - Open")
        for port in filtered_ports:
            logging.warning(f"Port: {port} - Filtered")
        for port in open_or_filtered_ports:
            logging.info(f"Port: {port} - Open/Filtered")

    def os_scan(self):
        target_os = os_detection.scan(self.target)

        if target_os:
            logging.info(f"[INFO] Système d'exploitation détecté : {target_os}")
        else:
            logging.warning("[[red]-[/red]] [ERROR] Impossible de détecter le système d'exploitation")

    def send_icmp(self, target, result, index):
        target = str(target)
        host_found = []
        pkg = scapy.IP(dst=target) / scapy.ICMP()
        answers, unanswered = scapy.sr(pkg, timeout=3, retry=2, verbose=0, iface=self.interface if self.interface else None)
        answers.summary(lambda r: host_found.append(target))

        if host_found:
            result[index] = host_found[0]

    def service_scan(self, target):
        open_ports = [21, 22, 80, 433, 3306, 8080]
        
        for port in open_ports:
            service = service_detection.scan_service(target, port)
            logging.info(f"Port {port} : {service}")
        
    def discover_net(self, ip_range=24, max_threads=50):  # Ajout d'une limite de threads
        protocol = self.protocol or "ICMP"

        if protocol != "ICMP":
            logging.warning(f"[WARNING]  {protocol} n'est pas supporté ! Utilisation forcée d'ICMP.")
            logging.critical("[ERROR] Protocole invalide pour ce scan.")
            return False

        try:
            # Vérification et formatage de l'adresse IP de base
            base_ip_parts = self.my_ip.split('.')
            if len(base_ip_parts) != 4:
                logging.critical("[ERROR] Adresse IP locale invalide !")
                return False

            base_ip = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.0/{ip_range}"
            network = ipaddress.ip_network(base_ip, strict=False)
            hosts = list(network.hosts())

        except ValueError as e:
            logging.critical(f"[ERROR] Erreur avec l'adresse IP fournie : {e}")
            return False

        logging.info(f"[INFO] Scan ICMP en cours sur {len(hosts)} hôtes...")

        # Initialisation de la barre de progression
        bar = ChargingBar("[INFO]  Scan en cours...", max=len(hosts))
        results = [None] * len(hosts)

        # ✅ Ajout d'une limite de threads pour éviter de surcharger le CPU
        semaphore = Semaphore(max_threads)

        # Gestion des threads
        threads = []
        for i, host in enumerate(hosts):
            semaphore.acquire()  # Bloque si trop de threads sont en cours

            def worker(target_host, index):
                self.send_icmp(target_host, results, index)
                semaphore.release()  # Libère un slot après exécution

            t = Thread(target=worker, args=(host, i))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
            bar.next()  # Mise à jour de la barre de progression

        bar.finish()  # Fin de la barre de progression

        # Résultat final
        hosts_found = [i for i in results if i is not None]
        
        if hosts_found:
            logging.info(f"[INFO] {len(hosts_found)} hôtes actifs trouvés :")
            for host in hosts_found:
                logging.info(f"[INFO]  ➜ {host}")
        else:
            logging.warning("[WARNING] Aucun hôte actif trouvé.")

        return bool(hosts_found)  # Retourne `True` si au moins un hôte est trouvé



def arguments():
    parser = argparse.ArgumentParser(
        description="ASTSU - Advanced Security Testing and Scanning Utility",
        usage="\n\t astsu.py [options] target",
    )
    
    #Optionq de scan
    parser.add_argument('-sC', '--scan-common', help="Scan des ports courants", action="store_true")        
    parser.add_argument('-sA', '--scan-all', help="Scan de tous les ports (0-65535)", action="store_true")
    parser.add_argument('-d', '--discover', help="Découverte des hôtes sur le réseau", action="store_true") 
    parser.add_argument('-sO', '--scan-os', help="detection de l'OS", action="store_true")
    parser.add_argument('-sV', '--scan-service', help="Détection des services actifs", action="store_true")
    
    #Paramètre de configuration
    parser.add_argument('-i', '--interface', help="Interface réseau à utiliser")
    parser.add_argument('-t', '--timeout', help="Timeout pour les requêtes", type=int, default=5)
    parser.add_argument('-p', '--protocol', help="Protocole à utiliser (TCP, UDP, ICMP)", choices=['TCP', 'UDP', 'ICMP'])
    parser.add_argument('-o', '--output', help="Fichier de sortie pour enregistrer les résultats")
    parser.add_argument('-v', '--version', help="Affiche la version", action="store_true")
    parser.add_argument('-st', '--stealth', help='Utiliser le scan stealth (TCP SYN)', action='store_true')
    
    #Cible du scan
    parser.add_argument('Target', nargs='?', help='Adresse IP ou domaine de la cible')
    
    args = parser.parse_args()
    
    #Verification des arguments (affiche l'aide si aucun argument est scpécifié)
    if not (args.scan_common or args.scan_all or args.discover or args.scan_os or args.scan_service or args.version):
        parser.print_help()
        sys.exit(1)
    
    # Vérification de la cible pour les scans nécessitant une IP/Domaine
    if (args.scan_common or args.scan_all or args.scan_os or args.scan_service) and not args.Target:
        logging.error("Erreur : vous devez spécifier une cible (ex: 192.168.1.1)")
        sys.exit(1)
    
    return (args, parser)

if __name__ == '__main__':
    args, parser = arguments()
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80))
        ip = s.getsockname()[0]
        s.close()
        
    except ValueError as e :
        logging.critical(f"[ERROR] Erreur avec l'adresse IP fournie : {e}")
        
    scanner = Scanner(
        target=args.Target,
        my_ip=ip,
        protocol=args.protocol if args.protocol else "TCP",
        timeout=args.timeout, 
        interface=args.interface
    )
    
    if args.version:
        print("\n")
        logging.info(f"\t ASTU Version: {__version__}")
        print("\n")
        sys.exit(0) 
    
    if args.output:
        output_file = args.output
        with open(output_file, "w") as f:
            f.write("\t\t===== ASTU Scan Report =====\n\n")
        # logging.info(f"[INFO] Les résultats seront enregistrés dans : {output_file}")


    print("\n\tBienvenue dans ASTU - Advanced Network Scanner 🚀\n")

    if args.scan_common:
        print(f"Scan des ports courants sur {args.Target}")
        results = scanner.common_scan(stealth=args.stealth)
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n".join(set(results)) + "\n")


    if args.scan_all:
        logging.info(f"Scan de tous les ports sur {args.Target}")
        results = scanner.range_scan(start=0, end=65535, stealth=args.stealth)
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n".join(results) + "\n")
                
    if args.discover:
        logging.info("Découverte des hôtes sur le réseau local")
        results = scanner.discover_net()
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n".join(results) + "\n")

    if args.scan_os:
        logging.info(f"Détection de l'OS de la cible {args.Target}")
        results = scanner.os_scan()
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n".join(results) + "\n")

    if args.scan_service:
        logging.info(f"Détection des services actifs sur {args.Target}")
        results = scanner.service_scan(args.Target)
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n".join(results) + "\n")
