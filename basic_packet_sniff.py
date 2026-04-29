# https://blogs.canisius.edu/cybersecurity/2024/04/26/using-scapy-to-evaluate-wifi-packets/

from scapy.all import *

# packets = sniff(count=10)
# packets.summary()

class Basic_Sniffer():

    def packet_callback(packet):
        print(packet.summary())
    packets = sniff(filter="tcp", prn=packet_callback, count=10)


if __name__ == '__main__':
    bs = Basic_Sniffer()