#!/usr/bin/env python

# DoS_Attack Tool 

'''
this tool will help you to detect any Deauth attacks 
By analyzing the output packet count, you can detect whether it falls under the DoS attack
or normal behavior

'''

from scapy.all import *
from scapy.layers import Dot11
from datetime import datetime

# get Network Interface from user
interface = raw_input('Enter your Network Interface > ')

# set Packet Counter 
Packet_Counter = 1

# dictionary to store deauth packet counts per source MAC address
deauth_counts = {}

# threshold for deauth packet counts
threshold = 10

# extract info of the packet 
def info(packet):
    global Packet_Counter
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 12:  # Check for deauth frame
            src = packet.addr2  # Source MAC address
            print(f"[+] Deauthentication Packet detected from {src} at {datetime.now()}")
            # Update deauth counts for the source MAC address
            deauth_counts[src] = deauth_counts.get(src, 0) + 1
            Packet_Counter += 1
            if deauth_counts[src] >= threshold:
                print(f"[!] Potential Deauth Attack detected from {src} with {deauth_counts[src]} packets")
                # You can add additional actions here, like logging or blocking the source
                # Reset the count for this source to avoid repeated alerts
                deauth_counts[src] = 0

# Start Sniffing and Detecting Deauth Packets
sniff(iface=interface, prn=info)
