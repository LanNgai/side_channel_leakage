# https://medium.com/@ahmedsobhialii/deep-packet-capture-in-python-a-complete-guide-to-sniffing-techniques-54d650e403e1

import pyshark

cap = pyshark.LiveCapture(interface='eth0')
for packet in cap.sniff_continuously(packet_count=10):
    print(packet)