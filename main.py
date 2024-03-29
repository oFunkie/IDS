#!/usr/bin/python3

import os
import yaml
import subprocess
import re
from datetime import datetime
import pytz
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
from dotenv import load_dotenv
import time

load_dotenv()

#STATUS
plus = f'[+]'
info = f'[*]'
mini = f'[-]'
warn = f'[!]'
err = f'[ERR]'

def load_config():
    try:
        with open('config.yml', 'r') as config_file:
            config = yaml.safe_load(config_file)
            return config
    except FileNotFoundError:
        print(f'{err} Configuration file (config.yml) not found.')
        return None

def sendMail(sub, body):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("SENDER_EMAIL")
    receiver_email = os.getenv("RECEIVER_EMAIL")

    subject = f'{sub}'
    body = f'{body}'

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)

        server.sendmail(sender_email, receiver_email, message.as_string())

        print(f'{plus} Email was send ')

def whatTime():
    paris_timezone = pytz.timezone('Europe/Paris')
    heure_paris = datetime.now(paris_timezone).strftime('%H:%M:%S')
    return heure_paris

def getIPINFO(ip):
    URL = "https://ipinfo.io/" + ip
    page = requests.get(URL)
    result = page.text
    resultOneLine = " ".join(line.strip() for line in result.splitlines())
    res = resultOneLine.split()
    city = str(res[6]);city = city.replace('\"', "");city = city.replace(',', "")
    loc = str(res[12]);loc = loc.replace("\"", "");loc = loc[:len(loc)-1]
    reg = str(res[8]);reg = reg.replace("\"", "");country = str(res[10]);country = country.replace("\"", "")
    location = f"Location: {country} {reg} {city} at {loc}"
    return location

def ban(ip):
    path = "/etc/hosts.deny"
    with open(path, 'a') as file:
        file.write(f"sshd: {ip}")

def getOut(config):
    if not config:
        return

    whitelisted_ips = config.get('whitelisted_ips', [])
    message = config.get('message', 'You will be banned and report in 5 seconds.')

    who = subprocess.Popen('who', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    who_output, err = who.communicate()
    who_output = who_output.decode('utf-8')
    who_lines = who_output.split('\n')

    for line in who_lines:
        try:
            # Take the targeted info
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            pts_match = re.search(r'pts/\d+', line)
            user_match = re.search(r'^(\S+)', line)

            if ip_match and ip_match.group() in whitelisted_ips:
                print(f'{info} Whitelisted IP {ip_match.group()} connected. Ignoring.')
                continue

            location = getIPINFO(ip_match.group())
            heure_paris = whatTime()

            try:
                subject_intrusion = f"INTRUSION ON {socket.gethostname()}"
                body_intrusion = f"User {user_match.group()} connected to {socket.gethostname()} from ip: {ip_match.group()} at {heure_paris} in {location}"
                sendMail(subject_intrusion, body_intrusion)
            except Exception as MAIL_ERR:
                print(f'{err} {MAIL_ERR}')
                continue

            print(f'{plus} SSH user {user_match.group()} from {ip_match.group()}, pseudo-terminal slave: {pts_match.group()}')

            info_log = f"{warn} UNKNOW USER {user_match.group()}:{ip_match.group()} connected from {location}"
            print(f"{info} Sending message: \"{message}\" to user {user_match.group()}")
            print(info_log)
            log(info_log)
            # Send message to the user
            os.system(f'echo \"{message}\" | write {user_match.group()} {pts_match.group()} && sleep 5')
            print(f'{plus} Message was send to user {user_match.group()}\n')

            ps_raw_command = ['ps', '-t', pts_match.group()]
            ps = subprocess.Popen(ps_raw_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ps_output, err = ps.communicate()
            pid_match = re.search(r'^\s*(\d+)', ps_output.decode('utf-8'), re.MULTILINE)
            try:
                if pid_match:
                    pid = pid_match.group(1)
                    print(f'{plus} PID of {pts_match.group()}: {pid}\n')
                    kick_raw_command = ['sudo', 'kill', '-HUP', pid]
                    subprocess.run(kick_raw_command)
                    kick_log = f'{plus} User {user_match.group()} was kicked (PID:{pid})'
                    print(kick_log)
                    log(kick_log)
                    ban(ip_match.group())
                    ban_log = f'{plus} User was ban with ip: {ip_match.group()}, (look in /etc/hosts.deny)'
                    print(ban_log)
                    log(ban_log)
                else:
                    print(f'{warn} No PID for {pts_match.group()}')
            except Exception as PID_ERR:
                print(f'{err} {PID_ERR}')
                continue
        except Exception as WHO_ERR:
            print(f"{err} {WHO_ERR}")
            continue

def log(loged_line):
    path_log = "intrusion.log"
    heure_paris_log = whatTime()
    with open(path_log, 'a') as log:
        log.write(f"\n{heure_paris_log} {loged_line}")

if __name__ == "__main__":
    while True:
        config = load_config()
        getOut(config)
        time.sleep(60)