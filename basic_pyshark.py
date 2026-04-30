## https://medium.com/@ahmedsobhialii/deep-packet-capture-in-python-a-complete-guide-to-sniffing-techniques-54d650e403e1
import asyncio
import pyshark


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

cap = pyshark.LiveCapture(interface='(wlp0s20f0u1u4u1)', display_filter='(wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x01 || wlan.fc.type_subtype == 0x02 || wlan.fc.type_subtype == 0x03 ||  wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05)')

calibration = -44 # calibration device's RSS at a distance of 1 meter                              
condition = 2.5 # accuracy notes

def rssi_to_distance(rssi):
    return round(10 ** ((calibration - rssi) / (10 * condition)), 2)

for packet in cap.sniff_continuously():
 
    mac = packet.wlan.sa # source MAC address
    ssid = packet.wlan.get_field_value('ssid') # ssid field
    bssid = packet.wlan.bssid
    rssi = int(packet.radiotap.dbm_antsignal)
    distance = rssi_to_distance(rssi)
    
    print(f"MAC: {mac} | SSID: '{ssid}' |  BSSID: '{bssid}' | Signal: {rssi} dBm | Distance: {distance} m")

