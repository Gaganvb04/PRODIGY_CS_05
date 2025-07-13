# Network Packet Analyzer (Python + Scapy)
Ethical Notice: This tool is for educational purposes only. Do not use it on networks without proper authorization. Unauthorized packet sniffing is illegal and unethical.

**Features**<br>
-Real-time packet capture<br>   
-Shows source & destination info<br>
-Displays protocol and port details<br>
-Prints readable payload (if possible)<br>
-Clean exit with Ctrl + C

**Requirements**<br>
Python 3.8+

scapy library

Npcap (Windows only) for packet capture backend

**Install Scapy:**<br>
pip install scapy<br>
Install Npcap on Windows:<br>
Download: https://nmap.org/npcap

During installation, check:

"Install Npcap in WinPcap API-compatible Mode"

**How to Run**<br>
Windows (Run terminal as Administrator):<br>
python Packet_Analyzer.py<br>
Linux/macOS:<br>
sudo python3 Packet_Analyzer.py<br>
The tool will start sniffing packets. Press Ctrl + C to stop it.

**Sample Output**<br>
 Packet Captured:
    Protocol      : TCP
    Source IP     : 192.168.1.10
    Destination IP: 172.217.167.78
    Source Port   : 52314
    Destination Port: 443
    Payload       : GET / HTTP/1.1
                    Host: example.com

**Legal & Ethical Use**<br>
This tool is designed for:<br>
-Cybersecurity education<br>
-Ethical hacking labs<br>
-Network diagnostics<br>
-Do NOT use this on public or third-party networks without consent.

**Author**
Gagan V B
www.linkedin.com/in/gaganvb04

