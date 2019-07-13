# TinyPacketSniffer
Simple packet sniffer for linux distributions.
## Project Description
This is a basic level python3 packet sniffer which uses linux socket function on port 65565 for raw packet on every port, both incoming or outgoing and extracts information including IP protocol, source MAC address, source IP address, source port, destination MAC address, destination IP address and destination port.
## Running Project
You will need root access to bind socket for sniffing, write the following command in terminal, in the directory where .py extension file is.
```
sudo python3 sniffer.py
```
## Sample result:
