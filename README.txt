# Deauth Attack Detector Python Tool

This tool helps you detect Deauthentication (Deauth) attacks by analyzing network traffic. 
It uses the scapy library to sniff packets and identify deauth frames.

## Features

- Detects Deauth packets in real-time.
- Tracks the number of Deauth packets from each source MAC address.
- Alerts when the number of Deauth packets from a single source exceeds a threshold.

## Requirements

- Python 2.7 or higher
- scapy library

## Usage

1. Install scapy if you haven't already:

   ```bash
   pip install scapy

2. Run the tool and provide the network interface to sniff:

   python DoS_Attack_Detector.py

