## https://medium.com/@ahmedsobhialii/deep-packet-capture-in-python-a-complete-guide-to-sniffing-techniques-54d650e403e1
import asyncio
import pyshark

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
    
    def live_data(self, interface):
    
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        cap = pyshark.LiveCapture(interface= interface, 
                                #   display_filter='(wlan.fc.type_subtype == 0x00' +
                                #   '|| wlan.fc.type_subtype == 0x01' +
                                #   '|| wlan.fc.type_subtype == 0x02' + 
                                #   '|| wlan.fc.type_subtype == 0x03 ' + 
                                #   '||  wlan.fc.type_subtype == 0x04 ' + 
                                #   '|| wlan.fc.type_subtype == 0x05 ' + 
                                #   '|| wlan.fc.type_subtype == 0x08)', 
                                  debug=True)

        for packet in cap.sniff_continuously():
            
            type = packet.wlan.fc_type
            subtype = packet.wlan.fc_subtype
            mac = packet.wlan.sa # source MAC address
            
            ssid = packet.wlan.get_field_value('ssid') # ssid field
            destination_bssid = packet.wlan.ra
            
            # Lan testing why we couldn't get the SSID
            # ssid = str(packet['wlan_mgt'].get_field_value('ssid') or '(wildcard)')
            # ssid = str(packet.wlan.mgt.ssid)
            
            bssid = packet.wlan.bssid
            rssi = int(packet.radiotap.dbm_antsignal)

            distance = self.rssi_to_distance(rssi)

            print(f"SubType: {subtype} | MAC: {mac} | SSID: '{ssid}'Destination BSSID : {destination_bssid} |  BSSID: '{bssid}' | Signal: {rssi} dBm | Distance: {distance} m")
        
        
   

   

if __name__ == '__main__':
    pd = Pyshark_distance()
    interface = pd.user_input()
    pd.live_data(interface)
