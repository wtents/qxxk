#!/bin/sh
uci set wireless.radio0.disabled=1
ifconfig wifi0 down
uci set wireless.@wifi-iface[1].mode=sta
uci set wireless.@wifi-iface[1].network=wwan
uci set wireless.@wifi-iface[1].ssid=IWF_TESTAP_AC
uci set wireless.wifi1.channel=36
uci set wireless.wifi1.hwmode=11a
uci set wireless.wifi1.htmode=VHT80
uci set wireless.@wifi-iface[1].wds=1
#uci set wireless.@wifi-iface[1].bssid=00:0E:8E:56:08:26
uci commit
/etc/init.d/network restart
sleep 5
udhcpc -i ath1
