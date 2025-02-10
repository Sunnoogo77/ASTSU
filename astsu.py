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
    def __init__(self, target=None, my_ip=None, protocol=None, timeout=5, interface=None, port=None):
        self.target = args.Target if args.Target else target
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
                print(f"⚠️  Machine {self.target} semble éteinte ou injoignable.")
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
                    print(f"⚠️  Machine {self.target} semble éteinte ou injoignable.")
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
                    print(f"⚠️  Machine {self.target} semble éteinte ou injoignable.")
                    return {port: 'Open/Filtered'}
                
                elif scan.haslayer(scapy.UDP):
                    return {port: 'Closed'}
                elif scan.haslayer(scapy.ICMP):
                    if int(scan.getlayer(scapy.ICMP).type) == 3 and int(scan.getlayer(scapy.ICMP).code) == 3:
                        return {port: 'Closed'}
    # def scan_port(self, stealth=None, target, port):
        
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
        
        sorted_results = sorted(
            [(port, "Open") for port in open_ports] +
            [(port, "Filtered") for port in filtered_ports] +
            [(port, "Open/Filtered") for port in open_or_filtered_ports] +
            [(port, "Closed") for port in closed_ports],
            key=lambda x: x[0]  # Trie par numéro de port
        )

        for i in range(len(sorted_results)):
            port, status = sorted_results[i]
            results_for_file.append(f"Port: {port} - {status}")
                    
        total = len(open_ports) + len(filtered_ports) + len(open_or_filtered_ports) + len(closed_ports)
        print(f"\n\t ✅ Scan terminé :{total} ports analysés dont : ")
        print(f"\t\t{len(open_ports)} - Open")
        print(f"\t\t{len(closed_ports)} - Closed")
        print(f"\t\t{len(filtered_ports)} - Filtered")
        print(f"\t\t{len(open_or_filtered_ports)} - Open/Filtered\n")
        
            
        return results_for_file
        
    def range_scan(self, start, end=None, stealth=None, sv=None):
        
        open_ports = []
        filtered_ports = []
        open_or_filtered_ports = []
        closed_ports = []
        protocol = self.protocol if self.protocol else "TCP"
        
        results_for_file = []
        
        if protocol == "TCP" and stealth:
            print("\n\n\tDémarrage - Scan furtif des ports --> TCP <--\n\n")
        elif protocol == "TCP" and not stealth:
            print("\n\n\tDémarrage - Analyse des port --> TCP <--\n\n")
        elif protocol == "UDP":
            print("\n\n\tDémarrage - Scan du port --> UDP <-- \n\n")
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
                    "open/filtered": open_or_filtered_ports,
                    "closed": closed_ports
                }

                open_ports, filtered_ports, open_or_filtered_ports, closed_ports= self.handle_port_response(
                    ports_saved=ports_saved, response=scan, port=port
                )
        sorted_results = sorted(
            [(port, "Open") for port in open_ports] +
            [(port, "Filtered") for port in filtered_ports] +
            [(port, "Open/Filtered") for port in open_or_filtered_ports] +
            [(port, "Closed") for port in closed_ports],
            key=lambda x: x[0]
        )
        
        for i in range(len(sorted_results)):
            port, status = sorted_results[i]
            results_for_file.append(f"Port: {port} - {status}")

        total = len(open_ports) + len(filtered_ports) + len(open_or_filtered_ports) + len(closed_ports)
        print(f"\n\t ✅ Scan terminé :{total} ports analysés dont : ")
        print(f"\t\t{len(open_ports)} - Open")
        print(f"\t\t{len(closed_ports)} - Closed")
        print(f"\t\t{len(filtered_ports)} - Filtered")
        print(f"\t\t{len(open_or_filtered_ports)} - Open/Filtered\n")
    
        return results_for_file

    def os_scan(self):
        target_os = os_detection.scan(self.target)
        target_os_str = ''
        if target_os:
            print(f"\n\tSystème d'exploitation détecté : {target_os}\n")
            target_os_str = "OS detected : " + str(target_os)
        else:
            print("\n\t[[red]-[/red]] [ERROR] Impossible de détecter le système d'exploitation\n")
        return target_os_str
    
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
        results = []
        
        for port in open_ports:
            service = service_detection.scan_service(target, port)
            
            if service:
                
                if isinstance(service, list): 
                    formatted_service = ", ".join(map(str, service))
                elif isinstance(service, tuple):
                    formatted_service = ", ".join(map(str, service)) 
                elif isinstance(service, dict):
                    formatted_service = ", ".join([f"{key}:{value}" for key, value in service.items()])
                else: 
                    formatted_service = str(service).replace('\n', ' ').replace('\r', ' ')
                
                if port < 99:
                    print(f"Port {port}   : {formatted_service}")
                    results.append(f"Port {port} : {formatted_service}")
                elif port > 99 and port < 999:
                    print(f"Port {port}  : {formatted_service}")
                    results.append(f"Port {port} : {formatted_service}")
                elif port > 999:
                    print(f"Port {port} : {formatted_service}")
                    results.append(f"Port {port} : {formatted_service}")
            else:
                if port < 99:
                    print(f"Port {port}   : -")
                    results.append(f"Port {port}   : -")
                elif port > 99 and port < 999:
                    print(f"Port {port}  : -")
                    results.append(f"Port {port}  : -")
                elif port > 999:
                    print(f"Port {port} : -")
                    results.append(f"Port {port} : -")
                    
        return results
        
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
            semaphore.acquire()

            def worker(target_host, index):
                self.send_icmp(target_host, results, index)
                semaphore.release()  

            t = Thread(target=worker, args=(host, i))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
            bar.next()  

        bar.finish()  

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
    parser.add_argument('-sC', '--scan-common', help="Scan des ports courants", action="count")        
    parser.add_argument('-sA', '--scan-all', help="Scan de tous les ports (0-65535)", action="count")
    parser.add_argument('-sP', '--scan_port', help="Scan d'un port spécifique", type=int)
    parser.add_argument('-d', '--discover', help="Découverte des hôtes sur le réseau", action="count") 
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
    if not (args.scan_common or args.scan_all or args.discover or args.scan_os or args.scan_service or args.version or args.scan_port):
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
    except OSError:
        ip = "0.0.0.0"
        print("\n")
        logging.warning("⚠️  Connexion Internet absente. L'adresse IP locale ne peut pas être détectée.")
        logging.warning("⚠️  Assurez-vous d'être connecté au réseau avant de lancer un scan.")
    
        
    scanner = Scanner(
        target=args.Target,
        my_ip=ip,
        protocol=args.protocol if args.protocol else "TCP",
        timeout=args.timeout, 
        interface=args.interface
    )
    
    if args.version:
        print("\n")
        print(f"\t ASTU Version: {__version__}")
        print("\n")
        sys.exit(0) 
    
    if args.output:
        output_file = args.output
        with open(output_file, "w") as f:
            f.write("\t\t===== ASTU Scan Report =====\n\n")

    # print("\n\tBienvenue dans ASTU - Advanced Network Scanner 🚀\n")

    if args.scan_common:
        print(f"\n\tScan des ports courants sur {args.Target}")
        results = scanner.common_scan(stealth=args.stealth)
        if args.output:
            with open(output_file, "a") as f:
                f.write("\tCommon_scan results\n\n")
                f.write("\n".join(results) + "\n")
                
    if args.scan_all:
        print(f"\n\tScan de tous les ports sur {args.Target}")
        results = scanner.range_scan(start=0, end=65535, stealth=args.stealth)
        if args.output:
            with open(output_file, "a") as f:
                f.write("\tScan_All results\n\n")
                f.write("\n".join(results) + "\n")
                            
    if args.discover:
        logging.info("Découverte des hôtes sur le réseau local")
        results = scanner.discover_net()
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n".join(results) + "\n")

    if args.scan_os:
        print(f"\nDétection de l'OS de la cible {args.Target}")
        results = scanner.os_scan()
        if args.output:
            with open(output_file, "a") as f:
                f.write("\tOS detection Results results\n\n")
                f.write(results)

    if args.scan_service:
        print(f"\n\n\tDétection des services actifs sur {args.Target}\n")
        results = scanner.service_scan(args.Target)
        print("\n")
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n".join(results) + "\n")

    if args.scan_port:
        if not args.Target:
            print("\n\t❌ Erreur : Vous devez spécifier une cible pour scanner un port spécifique (ex: python3 astsu.py 192.168.1.1 -sP 80\n")
            sys.exit(1)
        print(f"\n🔍 Scan du port {args.scan_port} sur {args.Target}")
        
        scanner.target = args.Target
        result = scanner.port_scan(port=args.scan_port, stealth=args.stealth)
        if result:
            for port, status in result.items():
                print(f"\n\t✅ Port: {port} - {status}\n")
            
            if args.output:
                with open(output_file, "a") as f:
                    f.write("\tPort_Scan results\n\n")
                    f.write(f"Port : {args.scan_port} - {status}")