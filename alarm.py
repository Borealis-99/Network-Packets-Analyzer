#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

incident_number = 0  # used to keep track of the number of incidents detected
FTPUsername = ""
FTPPassword = ""


def packetcallback(packet):
    global incident_number
    global FTPUsername
    global FTPPassword

    try:
        if packet.haslayer("TCP"):  # if "TCP" in packet:
            # check for NULL scan:
            if packet["TCP"].flags == "":  # == 0
                incident_number += 1
                print(
                    f"ALERT #{incident_number}: NULL scan is detected from {packet['IP'].src} (port number: {packet['TCP'].dport})")

            # check for FIN scan:
            if packet["TCP"].flags == "F":  # == 0x01
                incident_number += 1
                print(
                    f"ALERT #{incident_number}: FIN scan is detected from {packet['IP'].src} (port number: {packet['TCP'].dport})")

            # check for Xmas scan:
            if packet["TCP"].flags == "FPU":  # == 0x29
                incident_number += 1
                print(
                    f"ALERT #{incident_number}: Xmas scan is detected from {packet['IP'].src} (port number: {packet['TCP'].dport})")

            # check for clear text credentials:
            if packet.haslayer(Raw):  # check if the packet has a payload
                payload = packet["TCP"].load.decode("ascii").strip() # packet[Raw].load.decode("utf-8", errors="ignore")

                # check for HTTP Basic Authentication:
                # if "Authorization: Basic" in payload:
                #     incident_number += 1
                #     credentials = payload.split(
                #         "Authorization: Basic")[1].strip()
                #     credentials = base64.b64decode(
                #         credentials).decode("utf-8")
                #     username, password = credentials.split(":")
                #     print(
                #         f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (HTTP) (username:{username}, password:{password})")
                if "Authorization: Basic" in payload:
                    incident_number += 1
                    credentials = payload.split("Authorization: Basic ")[1].split()[0]
                    credentials = base64.b64decode(credentials).decode("utf-8")
                    username, password = credentials.strip("'").split(":")
                    print(
                        f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (HTTP) (username:{username}, password:{password})")

                # check for FTP:
                if packet["TCP"].dport == 21:
                    # if "USER" in payload or "PASS" in payload:
                    #     for lines in payload.splitlines():
                    #         line = lines.split()
                    #         if "USER" == line[0]:
                    #             FTPUsername = line[1]
                    #         elif "PASS" == line[0]:
                    #             incident_number += 1
                    #             FTPPassword = line[1]
                    #             print(
                    #                 f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (FTP) (username:{FTPUsername}, password:{FTPPassword})")
                    #             FTPUsername = ""
                    #             FTPPassword = ""
                    if "USER" in payload:
                      FTPUsername = payload.splitlines()[0].split()[1] # FTPUsername = payload.split("USER")[1].strip()
                    if "PASS" in payload:
                      incident_number += 1
                      FTPPassword = payload.splitlines()[0].split()[1]
                      print(
                          f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (FTP) (username:{FTPUsername}, password:{FTPPassword})")
                      FTPUsername = ""
                      FTPPassword = ""

                # check for IMAP:
                if packet["TCP"].dport == 143:
                    if "LOGIN" in payload:
                        incident_number += 1
                        username, password = payload.splitlines()[0].split()[
                            2:]
                        print(
                            f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (IMAP) (username:{username}, password:{password[1:-1]})")

            # check for Nikto scan:
            # elif packet.haslayer("HTTP"):
            #     user_agent = packet["HTTP"].headers.get("User-Agent", "")
            #     if "Nikto" in user_agent:
            #         incident_number += 1
            #         print(f"ALERT #{incident_number}: Nikto scan is detected from {packet['IP'].src} ({packet['IP'].proto})")
            if packet["TCP"].dport == 80 and "Nikto" in packet["TCP"].load.decode("ascii").strip(): # packet["TCP"].flags == "PA"
                incident_number += 1
                print(
                    f"ALERT #{incident_number}: Nikto scan is detected from {packet['IP'].src} (port number: {packet['TCP'].dport})")

            # check for Server Message Block (SMB) scan:
            if packet["TCP"].dport == 139 or packet["TCP"].dport == 445:
                incident_number += 1
                print(
                    f"ALERT #{incident_number}: SMB scan is detected from {packet['IP'].src} (port number: {packet['TCP'].dport})") 

            # check for Remote Desktop Protocol (RDP) scan:
            if packet["TCP"].dport == 3389:
                incident_number += 1
                print(
                    f"ALERT #{incident_number}: RDP scan is detected from {packet['IP'].src} (port number: {packet['TCP'].dport})")

            # check for Virtual Network Computing (VNC) scan:
            if packet["TCP"].dport in range(5900, 5909):
                incident_number += 1
                print(
                    f"ALERT #{incident_number}: VNC scan is detected from {packet['IP'].src} (port number: {packet['TCP'].dport})")

    except Exception as e:
        # Uncomment the below and comment out `pass` for debugging, find error(s)
        # print(e)
        pass


# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(
    description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface',
                    help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
    try:
        print("Reading PCAP file %(filename)s..." %
              {"filename": args.pcapfile})
        sniff(offline=args.pcapfile, prn=packetcallback)
    except:
        print("Sorry, something went wrong reading PCAP file %(filename)s!" %
              {"filename": args.pcapfile})
else:
    print("Sniffing on %(interface)s... " % {"interface": args.interface})
    try:
        sniff(iface=args.interface, prn=packetcallback)
    except:
        print("Sorry, can\'t read network traffic. Are you root?")
