#! /usr/bin/env python3

# wifi-ap-scanner
# Wang Xinyu (2017)
# https://github.com/wang-xinyu/wifi-ap-scanner/blob/master/wifi_ap_scanner.py [accessed 29 04 2026]

import dbus
import sys

#https://github.com/linorobot/linorobot/issues/68#
from gi.repository import GLib as glib 
from dbus.mainloop.glib import DBusGMainLoop

class Client_Signal_Strength():
    def __init__(self):
        self.bus = dbus.SystemBus()
        self.NM = 'org.freedesktop.NetworkManager'
        self.bus.add_signal_receiver(
            None, None, self.NM + '.AccessPoint', None, None
        )
        
        nm = self.bus.get_object(self.NM, '/org/freedesktop/NetworkManager')
        self.devlist = nm.GetDevices(dbus_interface=self.NM)
        self.rssid = {}
        
    def dbus_get_property(self, prop, member, proxy):
        return proxy.Get(
            self.NM + '.' + member,
            prop,
            dbus_interface='org.freedesktop.DBus.Properties'
        )
        
    def populate_list(self):
        apl = []
        res = []
        
        for i in self.devlist:
            tmp = self.bus.get_object(self.NM, i)
            if self.dbus_get_property('DeviceType', 'Device', tmp) == 2:
                apl.append(
                    self.bus.get_object(self.NM, i) .GetAccessPoints(
                        dbus_interface=self.NM + '.Device.Wireless'
                    )
                )
                
        for i in apl: 
            for j in i:
                res.append(self.bus.get_object(self.NM, j))
        return res
                    
    def get_signal_strength(self):
        for i in self.populate_list():
            ssid = self.dbus_get_property('Ssid', 'AccessPoint', i)
            strength = self.dbus_get_property('Strength', 'AccessPoint', i)
            ssid_str = "".join("%s" % k for k in ssid)
            print ("SSID: %20s\t\t strength: %d" % (ssid_str, strength))
            
if __name__ == '__main__':
    DBusGMainLoop(set_as_default=True)
    css = Client_Signal_Strength()
    css.get_signal_strength()
    