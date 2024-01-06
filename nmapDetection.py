from scapy.all import *
from ids import info, warn, sendMail, heure_paris
import socket

ip_counter = {}

def detectNmap(pkt):
    if IP in pkt and pkt[IP].src != "127.0.0.1":
        src_ip = pkt[IP].src
        if src_ip in ip_counter:
            ip_counter[src_ip] += 1
        else: 
            ip_counter[src_ip] = 1
            
        print(f" {info} Possible nmap scan detected from {src_ip}")
        
while True:
    ip_counter = {}
    sniff(filter="tcp and (tcp[13] & 2 != 0)", prn=detectNmap, timeout=20)
    
    for ip, count in ip_counter.items():
        if count > 50
            print(f"{warn} The IP {ip} made {count} requests in the last minute.")
            subject_nmap = f"NMAP DETECTION"
            body_nmap = f"IP {ip} scanned {socket.gethostname()} with {count} requests at {heure_paris}"
            sendMail(ip, count)
