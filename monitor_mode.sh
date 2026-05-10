#!/bin/bash

#https://netbeez.net/blog/linux-how-to-configure-monitoring-mode-wifi-interface/
#https://stackoverflow.com/questions/5431909/returning-a-boolean-from-a-bash-function
#https://stackoverflow.com/questions/36371221/checking-the-success-of-a-command-in-a-bash-if-statement

read -p "Please enter the wireless interface: " interface

monitor_mode() {
	if iw $interface info | grep "type monitor"; then
		echo "Interface $interface is already in monitor mode."
		echo ""
		iw $interface info
		return 1
	else
		sudo ip link set $interface down
		sudo iw dev $interface set type monitor
		sudo ip link set $interface up
		return 0
	fi
}

if monitor_mode; then 
	echo "Success!!! $interface is in monitor mode!"
        iw dev
fi

