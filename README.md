Packet Sniffer
Overview
Packet Sniffer is a Python application built with Tkinter and Scapy that allows users to monitor network traffic on a specified interface. It provides real-time information about incoming packets, including source and destination IP addresses, protocols, and payload data.
Features
•	Interface Selection: Enter the network interface (e.g., eth0) to start sniffing packets.
•	Real-time Packet Display: View detailed information about each captured packet, including IP addresses, protocol types, and payloads.
•	Start and Stop Sniffing: Initiate packet sniffing with the ability to stop at any time.
•	Clear Logs: Easily clear the captured packet logs from the display.
Requirements
•	Python 3.x
•	Tkinter
•	Scapy
Installation
1.	Clone the repository:

cd packet-sniffer
2.	Install dependencies:
pip install -r requirements.txt
Usage
•	Run the application:
python packet_sniffer.py
•	Enter the network interface (e.g., eth0) in the provided field and click Start Sniffing.
•	Captured packets will be displayed in real-time. Use Stop Sniffing to halt packet capture.
•	Click Clear Logs to remove all captured packet logs from the display.

