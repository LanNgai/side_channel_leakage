## https://medium.com/@ahmedsobhialii/deep-packet-capture-in-python-a-complete-guide-to-sniffing-techniques-54d650e403e1
import asyncio
import pyshark
import binascii

class Pyshark_distance():
    
    
    def user_input(interface):
        print()
        # wlp0s20f0u1u4u1
        # wlp0s20f0u1u1
        interface = input("Please enter the name of the interface: ")
        return interface
    
    def rssi_to_distance(self, rssi):
        calibration = -44 # calibration device's RSS at a distance of 1 meter                              
        condition = 2.5 # accuracy notes
        return round(10 ** ((calibration - rssi) / (10 * condition)), 2)
    
    def get_ssid(self, packet): 
        try:
            raw = packet['wlan.mgt'].wlan_ssid
            return bytes.fromhex(str(raw)).decode('utf-8', errors='replace')
        except (KeyError, AttributeError, ValueError):
            pass
        
        try:
            ssid = packet['wlan_mgt'].get_field_value('ssid')
            if ssid:
                return str(ssid)
        except (KeyError, AttributeError):
            pass
        return '(wildcard)'
    
    def live_data(self, interface):
    
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        cap = pyshark.LiveCapture(interface= interface, 
                                  display_filter='(wlan.fc.type_subtype == 0x00' +
                                  '|| wlan.fc.type_subtype == 0x01' +
                                  '|| wlan.fc.type_subtype == 0x02' + 
                                  '|| wlan.fc.type_subtype == 0x03 ' + 
                                  '||  wlan.fc.type_subtype == 0x04 ' + 
                                  '|| wlan.fc.type_subtype == 0x05 ' + 
                                  '|| wlan.fc.type_subtype == 0x08)', 
                                # monitor_mode=True,
                                  debug=True)

        for packet in cap.sniff_continuously():
            
            type = packet.wlan.fc_type
            subtype = packet.wlan.fc_subtype
            mac = packet.wlan.sa # source MAC address
            
            # ssid = packet.wlan.get_field_value('ssid') # ssid field
            destination_bssid = packet.wlan.ra
            
            # Lan testing why we couldn't get the SSID
            # ssid = str(packet['wlan.mgt'].get_field_value('ssid') or '(wildcard)')
            # ssid = str(packet['wlan.mgt'].get_field_value('ssid'))

            # ssid = str(packet.wlan.mgt.ssid)
            
            # ssid = self.get_ssid(packet)
            # raw_ssid = packet.layers[1].wlan_ssid
            #ssid = bytes.fromhex(str(raw_ssid)).decode("utf-8", errors="replace")
            
            ssid = '(wildcard)'
            for layer in packet.layers:
                raw_ssid = getattr(layer, 'wlan_ssid', None)
                if raw_ssid:
                    try:
                        ssid_bytes = bytes.fromhex(str(raw_ssid).replace(':', '')) 
                        ssid = ssid_bytes.decode('utf-8', errors='replace').strip()
                        if not ssid:
                            ssid = '(wildcard)'
                    except (ValueError, UnicodeDecodeError):
                        ssid = str(raw_ssid)
                    break
            bssid = packet.wlan.bssid
            rssi = int(packet.radiotap.dbm_antsignal)

            distance = self.rssi_to_distance(rssi)

            print(f"SubType: '{subtype}'   | MAC: '{mac}' | SSID: '{ssid}'| Dest BSSID : '{destination_bssid}' | Signal: '{rssi}' dBm | Distance: '{distance}' m")
   

if __name__ == '__main__':
    pd = Pyshark_distance()
    interface = pd.user_input()
    pd.live_data(interface)