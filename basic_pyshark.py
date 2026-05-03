# Deep Packet Capture in Python: A Complete Guide to Sniffing Techniques
# by Ahmed Sobhi Ali (Jul 23 2025)
# https://stackoverflow.com/questions/11217674/how-to-calculate-distance-from-wifi-router-using-signal-strength [accessed 29 04 2026]

import asyncio
import pyshark


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

cap = pyshark.LiveCapture(interface='wlp0s20f0u1u1',display_filter='(wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x01 || wlan.fc.type_subtype == 0x02 || wlan.fc.type_subtype == 0x03 ||  wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05)')

for packet in cap.sniff_continuously():
 
    mac = packet.wlan.sa # source MAC address
    ssid = packet.wlan.get_field_value('ssid') # ssid field
    bssid = packet.wlan.bssid
    rssi = int(packet.radiotap.dbm_antsignal)
    
    print(f"MAC: {mac} | SSID: '{ssid}' |  BSSID: '{bssid}' | Signal: {rssi} dBm")

