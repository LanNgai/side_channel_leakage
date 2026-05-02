# Deep Packet Capture in Python: A Complete Guide to Sniffing Techniques
# by Ahmed Sobhi Ali (Jul 23 2025)
# https://medium.com/@ahmedsobhialii/deep-packet-capture-in-python-a-complete-guide-to-sniffing-techniques-54d650e403e1 [accessed 29 04 2026]

# Deep Packet Capture in Python: A Complete Guide to Sniffing Techniques
# by Ahmed Sobhi Ali (Jul 23 2025)
# https://stackoverflow.com/questions/11217674/how-to-calculate-distance-from-wifi-router-using-signal-strength [accessed 29 04 2026]

import asyncio
import pyshark

class Pyshark_distance():
    
    # Allows for user input to be the wireless interface used
    def user_input(interface):
        # wlp0s20f0u1u4u1
        # wlp0s20f0u1u1
        interface = input("Please enter the name of the interface: ")
        return interface
    
    def rssi_to_distance(self, rssi):
        calibration = -80 # calibration device's RSS at a distance of 1 meter, Lan's iPhone -90 and -80                             
        condition = 2 # accuracy notes
        return round(10 ** ((calibration - rssi) / (10 * condition)), 2)
    
    # This function 
    # def get_ssid(self, packet): 
    #     try:
    #         raw = packet['wlan.mgt'].wlan_ssid
    #         return bytes.fromhex(str(raw)).decode('utf-8', errors='replace')
    #     except (KeyError, AttributeError, ValueError):
    #         pass
        
    #     try:
    #         ssid = packet['wlan_mgt'].get_field_value('ssid')
    #         if ssid:
    #             return str(ssid)
    #     except (KeyError, AttributeError):
    #         pass
    #     return '(wildcard)'
    
    # This function handles live capture data and displays relevant output
    def live_data(self, interface):
    
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        cap = pyshark.LiveCapture(interface= interface, 
                                  display_filter='(wlan.fc.type_subtype == 0x00' +
                                #   '|| wlan.fc.type_subtype == 0x01' +
                                #   '|| wlan.fc.type_subtype == 0x02' + 
                                #   '|| wlan.fc.type_subtype == 0x03 ' + 
                                  '||  wlan.fc.type_subtype == 0x04 ' + 
                                  '|| wlan.fc.type_subtype == 0x05 )', 
                                #   '|| wlan.fc.type_subtype == 0x08)', 
                                # monitor_mode=True,
                                  debug=True)

        for packet in cap.sniff_continuously():
            
            type = packet.wlan.fc_type # Type
            subtype = packet.wlan.fc_subtype # Subtype
            mac = packet.wlan.sa # source MAC address
            
            destination_bssid = packet.wlan.ra # Destination BSSID
            
            # Lan testing why we couldn't get the SSID
            # ssid = packet.wlan.get_field_value('ssid') # ssid field (originally)

            # ssid = str(packet['wlan.mgt'].get_field_value('ssid') or '(wildcard)')
            # ssid = str(packet['wlan.mgt'].get_field_value('ssid'))

            # ssid = str(packet.wlan.mgt.ssid)
            
            # ssid = self.get_ssid(packet)
            # raw_ssid = packet.layers[1].wlan_ssid
            # ssid = bytes.fromhex(str(raw_ssid)).decode("utf-8", errors="replace")
            
            ssid = '(wildcard)' # Initial SSID value

            # For loop iterates layers within a captured packet
            for layer in packet.layers:
                raw_ssid = getattr(layer, 'wlan_ssid', None) # raw ssid gotten from the 'wlan_ssid' attribute, it returns 'None' if none are found
                if raw_ssid:
                    try:
                        ssid_bytes = bytes.fromhex(str(raw_ssid).replace(':', '')) # gets raw_ssid as a string and replaces any colons with nothing, bytes are gotten from the hex
                        ssid = ssid_bytes.decode('utf-8', errors='replace').strip() # the SSID bytes are decoded into readable uft-8 characters
                        if not ssid:
                            ssid = '(wildcard)' # Resets to initial SSID value if no SSID is resolved
                    except (ValueError, UnicodeDecodeError):
                        ssid = str(raw_ssid) # When there is an exception SSID value becomes the raw SSID in string format
                    break

            rssi = int(packet.radiotap.dbm_antsignal) # Relative signal strength taken from the packets' radiotap headers' antenna signal

            distance = self.rssi_to_distance(rssi) # Calls the function that calculates distance equivalent from the RSSI

            print(f"SubType: '{subtype}'   | MAC: '{mac}' | SSID: '{ssid}'| Dest BSSID : '{destination_bssid}' | Signal: '{rssi}' dBm | Distance: '{distance}' m")
   

if __name__ == '__main__':

    # Static variables for wireless interfaces used previously
    int_one = 'wlp0s20f0u1u1'
    int_two = 'wlp0s20f0u1u4u1'
    int_three = 'wlp0s20f0u3u1u4'

    pd = Pyshark_distance() # Instance of the class
    interface = pd.user_input() # Wireless interface taken from user input
    pd.live_data(interface) # Calls the function that gets the live data

    