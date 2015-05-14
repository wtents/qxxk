#!/bin/sh
LED_9382_2g=/sys/class/leds/db120\:green\:9382-2g/brightness
LED_USB=/sys/class/leds/db120\:green\:usb/brightness
LED_9344_5g=/sys/class/leds/db120\:green\:wlan-5g/brightness
LED_9344_2g=/sys/class/leds/db120\:green\:wlan-2g/brightness
LED_STATUS=/sys/class/leds/db120\:green\:status/brightness
LED_WPS=/sys/class/leds/db120\:green\:wps/brightness

while [ 2 ];do
	echo 0 > $LED_9382_2g
	echo 0 > $LED_USB
	echo 0 > $LED_9344_5g
	echo 0 > $LED_9344_2g
	echo 0 > $LED_STATUS
	echo 0 > $LED_WPS
	sleep 1

	echo 1 > $LED_9382_2g
	echo 1 > $LED_USB
	echo 1 > $LED_9344_5g
	echo 1 > $LED_9344_2g
	echo 1 > $LED_STATUS
	echo 1 > $LED_WPS
	sleep 1
done
