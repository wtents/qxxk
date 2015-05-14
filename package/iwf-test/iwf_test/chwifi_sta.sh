#!/bin/sh
uci set wireless.@wifi-iface[0].mode=sta
uci set wireless.@wifi-iface[0].ssid=IWF_TESTAP
uci commit
/etc/init.d/network restart
sleep 5
iwconfig wlan0 essid IWF_TESTAP mode managed
udhcpc -i wlan0
