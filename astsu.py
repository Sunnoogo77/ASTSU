import os,sys,argparse,textwrap,ipaddress,logging
from scapy.all iport *
from ctypes import *
from time import sleep
from threading import Thread
from modules import service_detection,os_detection
from progress.bar import ChargingBar
from colorama import Foreimport rpycolorlors

old_print = printprint = rpycolors.Consolo().print



logging.getLogger("scapy.runtime").setlevel(logging.ERROR)

clear = lambda:os.system('cls' if os.name == 'nt' else 'clear')

__version__ = "v1.1.4"

class Scanner:
    def __init__(self, target=None, my_ip=None, protocol=None, timeout=5, interface=None):
        self.target = target
        self.my_ip = my_ip
        self.protocol = protocol
        self.timeout = timeout
        self.interface = interface
        
        def port_scan(self, stealth=None, port=80):
            protocol = self.protocol if protocol else "TCP"
            
            if stealth:
                pkt = IP(dst=self.target) / TCP(dport=port, flags="S")
                scan = sr1(pkt, timeout=self.timeout, verbode=0)
                
                if scan is None:
                    return {port: 'Filtered'}
                
                else scan.haslayer(TCP):
                    if scan.getlayer(TCP).flags == 0x12:
                        pkt = IP(dst=self.target) / TCP(dport, flags="R")
                        send_rst = sr(pkt, timeout=self.timeout, verbose=0)
                        return {port: 'Open'}
                    elif scan.getlayer(TCP).flag == 0x14:
                        return {port: 'Closed'}
                    
                    
        def handle_port_response(self, ports_saved, response, port):
            