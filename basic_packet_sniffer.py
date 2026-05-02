# Using Scapy to Evaluate WiFi Packets
# by doughers (Apr 26 2024)
# https://blogs.canisius.edu/cybersecurity/2024/04/26/using-scapy-to-evaluate-wifi-packets/ [accessed 29 04 2026]

# Python Network Programming: Forging and Sniffing Packets with Scapy
# by exam collection (n.d.)
# https://www.examcollection.com/blog/python-network-programming-forging-and-sniffing-packets-with-scapy/ [accessed 29 04 2026]

# Deep Packet Capture in Python: A Complete Guide to Sniffing Techniques
# by Ahmed Sobhi Ali (Jul 23 2025)
# https://stackoverflow.com/questions/11217674/how-to-calculate-distance-from-wifi-router-using-signal-strength [accessed 29 04 2026]

# Scapy Tutorial: WiFi Security
# by Computer Science University of Toronto (n.d.)
# https://www.cs.toronto.edu/~arnold/427/18s/427_18S/indepth/scapy_wifi/scapy_tut.html [accessed 29 04 2026]

# Mastering Python for Advanced WiFi Analysis: A Hands-on Guide
# by Devwebtuts (Jun 30 2023)
# https://medium.com/@devwebtuts_50448/mastering-python-for-advanced-wifi-analysis-a-hands-on-guide-c1ca03e0e0 [accessed 29 04 2026]

from scapy.all import *

# packets = sniff(count=10)
# packets.summary()

class Basic_Sniffer():        

    def packet_callback(packet):
        print(packet.summary())
    
    packets = sniff(filter="tcp", prn=packet_callback, count=10)


if __name__ == '__main__':
    bs = Basic_Sniffer()