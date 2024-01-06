from scapy.all import *
from main import info, warn, sendMail
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
    sniff(filter="tcp and (tcp[13] & 2 != 0)", prn=detectNmap, timeout=30)
    
    for ip, count in ip_counter.items():
        if count > 50:
            print(f"{warn} The IP {ip} made {count} requests in the last minute.")
            subject_nmap = f"NMAP DETECTION"
            body_nmap = f"IP {ip} scanned {socket.gethostname()} with {count} requests"
            sendMail(ip, count)


#ubuntu@vps-3ab1b7c2:/etc/systemd/system$ bat serverMC.service
#───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
#       │ File: serverMC.service
#───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
#   1   │ [Unit]
#   2   │ Description=Minecraft Server pour la team
#   3   │ After=network.target
#   4   │
#   5   │ [Service]
#   6   │ User=ubuntu
#   7   │ Group=ubuntu
#   8   │
#   9   │ WorkingDirectory=/home/ubuntu/MinecraftSERV
#  10   │ ExecStart=bash start.sh
#  11   │
#  12   │ Restart=always
#  13   │
#  14   │ [Install]
#  15   │ WantedBy=multi-user.target