Network Packet Analyzer

A simple packet sniffer built using Python and Scapy to understand how network communication works in real time.

What This Project Does

This tool captures live network packets and shows basic details like source IP, destination IP, protocol type, packet size, and payload data. It is mainly built for learning networking and cybersecurity concepts.

Features

Captures real-time network traffic

Shows IP addresses and protocol type

Supports TCP, UDP, and ICMP filtering

Saves packet logs to a file

Lists available network interfaces

Tech Used

Python

Scapy

How To Run

Clone the project:

git clone https://github.com/Aishwaryeahh-cy/-PRODIGY_Trackcode_TaskNumber.git


Go inside folder:

cd PRODIGY_Trackcode_TaskNumber


Install dependencies:

pip install -r requirements.txt


Run the sniffer:

python packet_sniffer.py

Useful Commands

Capture limited packets:

python packet_sniffer.py --count 5


Filter TCP traffic:

python packet_sniffer.py --tcp


Save packets to file:

python packet_sniffer.py --log packets.txt


List network interfaces:

python packet_sniffer.py --list-interfaces

Note

Run the program with administrator/root permission. Windows users must install Npcap.

Disclaimer

This project is only for educational and authorized testing purposes.
