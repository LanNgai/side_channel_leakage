# https://medium.com/@ahmedsobhialii/deep-packet-capture-in-python-a-complete-guide-to-sniffing-techniques-54d650e403e1
import asyncio
import pyshark


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

cap = pyshark.LiveCapture(interface='wlp0s20f3',display_filter='wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05')

for packet in cap.sniff_continuously():
    try: 
        print("Scanning.......")
        mac = packet.wlan.sa
        ssid = packet.wlan_mgt.ssid
        ssid_str = "".join("%s" % k for k in ssid)
        rssi = packet.radiotap.dbm_antsignal
        
        print("MAC: %c | SSID: %s | Signal Strength: %d dBm" % (mac, ssid_str, rssi))
        
    except AttributeError:
        pass