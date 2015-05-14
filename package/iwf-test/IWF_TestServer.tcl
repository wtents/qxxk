#!/usr/bin/tclsh8.5
#===============Test Device Default Config================
set ::server_port 9900
set ::client_name KenChang
set ::client_passwd IWF300

#=================Wireless Test Condition=================
set ::testserver "172.16.1.254"
set ::testessid "IWF_TESTAP_AC"
set ::iface "ath1"
set ::sig_limit -55
#=========================================================


#0. Transfer Basic Infos  
proc device_info {} {
	if {[file exist /etc/openwrt_version]==1} {
		set f [open /etc/openwrt_version r]
		set version [lindex [split [read $f] '\n'] 0]
		close $f
	} else {
		set version "unknown"
	}
 
	set mac_place [split [exec find /sys/devices/platform/ -name address] '\n']
	foreach i $mac_place {
		set f [open $i r]
		lappend mac [lindex [split [read $f] '\n'] 0]
		close $f
	}
	return "Version:$version $mac"
}

#1. Check CPU
proc check_cpu {} {
	set f [open /proc/cpuinfo r]
	set cpuinfo [split [read $f] '\n']
	set cpu_model_i [lsearch -glob $cpuinfo "cpu model*"]
	set cpu_model [lindex [split [lindex $cpuinfo $cpu_model_i] ':'] 1]
	return $cpu_model
	close $f
}

#2. Check DDR2 RAM (Check Write to /tmp (ram mount point))   
proc check_ram {} {
	while { 1 } {
		set ram_usage [lindex [lindex [split [exec df /tmp ] '\n'] 1] 4]
		set ram_usage_int [string range $ram_usage 0 end-1] 
 
		if { $ram_usage_int < 70 } {
			set f1 [open /dev/mtd4 r] 
			set rawdata [read $f1] 
			close $f1 
 
			set f2 [open /tmp/TESTFILE a] 
			if {[catch {puts $f2 $rawdata} err]} {
				return "$ram_usage Err:$err" 
				close $f2 
			} else { 
				close $f2
			} 
		}
                             
		if { $ram_usage_int >= 70 } {
			file delete /tmp/TESTFILE
			return "OK"
			break 
		}
		puts $ram_usage
	}
}                  
 
#3. Check PCI interface
proc check_pci {} {
	set pci_i ""
	set dmesg [split [exec dmesg] '\n']
	set pci_i [lsearch -all -glob $dmesg "*pci*"]

	foreach i $pci_i {
		set pci_info [lindex $dmesg $i]
		if {[lsearch -glob $pci_info "*type*"]!=-1} {
			return [lindex $pci_info 4]
		}
	}
} 

#4. Check USB interface
proc check_usb {} {
	set usb_i ""
	set dmesg [split [exec dmesg] '\n']
	set usb_i [lsearch -all -glob $dmesg "*USB*"]

	foreach i $usb_i {
		set usb_info [lindex $dmesg $i]
		if {[string match [lrange $usb_info end-2 end] "USB hub found"]==1} {
			return [lrange $usb_info 2 end]
		}
	}
}

#5. Check UART interface
proc check_uart {} {
	after 3000
	puts "Transfer a uart msgs"
	exec /iwf_test/uart-test output
}

#6. Check LED action
proc check_led {} {
	set ledfile_rssi_hi "/sys/class/leds/ap135:green:rssi-hi/brightness"
	set ledfile_rssi_md "/sys/class/leds/ap135:green:rssi-md/brightness"
	set ledfile_rssi_lo "/sys/class/leds/ap135:green:rssi-lo/brightness"
	set ledfile_status "/sys/class/leds/ap135:green:status/brightness"
	set ledfile_wlan_2g "/sys/class/leds/ap135:green:wlan-2g/brightness"
	set ledfile_redstatus "/sys/class/leds/ap135:red:status/brightness"

	set i 0
	set br 0
	while { $i < 3 } {
		if { $br==0 } {
			set br 1
		} else {
			set br 0
			incr i
		}

		set f1 [open $ledfile_rssi_hi w]
		set f2 [open $ledfile_rssi_md w]
		set f3 [open $ledfile_rssi_lo w]
		set f4 [open $ledfile_status w]
		set f5 [open $ledfile_wlan_2g w]
		set f6 [open $ledfile_redstatus w]

		puts $f1 $br
		puts $f2 $br
		puts $f3 $br
		puts $f4 $br
		puts $f5 $br
		puts $f6 $br

		close $f1
		close $f2
		close $f3
		close $f4
		close $f5
		close $f6

		after 1000
	}
}

#7. Check Buttons
proc check_button {} {
	set resetb 0
	set wpsb 0

	#Avoid affect system, remove button control privilege
	set sf_w [file exists /etc/hotplug.d/button/50-wps]
	if { $sf_w==1 } {
		file rename /etc/hotplug.d/button/50-wps /etc/hotplug.d/button/50-wps.bak
	}
	file copy -force /iwf_test/button_wps /etc/hotplug.d/button/50-wps

	after 10000
	set log_f [open /tmp/button_test r]
	set log [lrange [split [read $log_f] '\n'] 0 end-1]
	foreach i $log {
		set button_type [lindex $i 0]
		if { [string match $button_type "WPS"]==1 } { set wpsb 1 }
	}

	#Restore origin button control srcipts
	file delete /etc/hotplug.d/button/50-wps
	if { $sf_w==1 } {
		file rename /etc/hotplug.d/button/50-wps.bak /etc/hotplug.d/button/50-wps
	}

	puts "RESET:$resetb WPS:$wpsb"
	return "RESET:$resetb WPS:$wpsb"
}

#8. Check NAND flash 
proc check_flash {} {
	set mtd_part ""
	set mtd_f [open /proc/mtd r]
	set mtd_data [lrange [split [read $mtd_f] '\n'] 1 end-1]
	close $mtd_f

	foreach i $mtd_data {
		lappend mtd_part [lindex [split $i ':'] 0]
	}

	foreach i $mtd_part {
		set fi [open /dev/$i r]
		puts "READ /dev/$i to RAWDATA"
		if {[catch {set rawdata [read $fi]} err]} {
			return "Err:$err"
			close $fi
		} else {
			puts "$i:OK"
			close $fi
		}

		set fo [open /tmp/TESTFILE w] 
		puts "WRITE RAWDATA to /tmp" 
		if {[catch {puts $fo $rawdata } err]} {
			return "Err:$err"
			close $fo
		} else {
			puts "$i:OK"
			close $fo
		}
	}

	if {$err==""} {
		return "OK"
	}
	file delete /tmp/TESTFILE
}

#9. Check Ethernet 
proc check_ethernet {} {
	exec /iwf_test/seteth.sh
	return "OK"
}

#10. Check Wireless
proc check_wireless {} {
	set result ""
	foreach inf $::iface { 
		#Patch for special MP-test environment
#		if {[string match $inf "wlan0"]==1} {
#			exec /iwf_test/chwifi_sta.sh
#			set ssid [lindex $::testessid 0]
#		}
		if {[string match $inf "ath1"]==1} {
			exec -ignorestderr /iwf_test/chwifi_ac_sta.sh
			set ssid [lindex $::testessid 1]
		}

#		after 10000
#		exec iwconfig $inf essid $ssid mode managed
#		exec udhcpc -i $inf

		if {[catch {exec ping -c 3 $::testserver} err]} {
			puts "Ping check FAIL" 
			set res "$inf Ping check failed"
		} else { 
 
			set res "NULL"
 
			for {set i 0} {$i<5} {incr i} {
#				set data [split [exec iw $inf station dump] '\n']
				set data [split [exec iwconfig $inf] '\n']
				set signal_i [lsearch -glob $data "*Signal*"]
 
				set signal1 [lindex [split [lindex [lindex $data $signal_i] 3] '='] 1]
				set signal2 [string range [lindex [lindex $data $signal_i] 2] 1 end-1]
				set signal3 [string range [lindex [lindex $data $signal_i] 3] 0 end-1]
				if {[string match $inf "ath1"]==1} { 
					set signal2 $signal1
					set signal3 $signal1 
				} 

				puts "SIGNAL1:$signal1"
				puts "SIGNAL2:$signal2"
				puts "SIGNAL3:$signal3"

				if {$signal1>=$::sig_limit && $signal2>=$::sig_limit && $signal3>=$::sig_limit} {
					set res "$inf PASS"
					puts "$i:$res"
				} else {
					set res "$inf FAIL"
					puts "$i:$res"
					break
				}
				after 1000
			}
		}
		append result "$res ( $signal1 $signal2 $signal3 ) "
	}
	file delete /overlay/etc/config/wireless
	return "RESULT:$result"
}
#11. Burn MAC address to art partition
proc burn_mac {mac0 mac1 mac2} {
	if {[string match $mac0 "NULL"]!=1} {
		set mac0_1 [string range $mac0 0 1] 
		set mac0_2 [string range $mac0 2 3] 
		set mac0_3 [string range $mac0 4 5] 
		set mac0_4 [string range $mac0 6 7] 
		set mac0_5 [string range $mac0 8 9] 
		set mac0_6 [string range $mac0 10 11] 
		exec -ignorestderr /usr/bin/modify_mac.sh eth0 $mac0_1 $mac0_2 $mac0_3 $mac0_4 $mac0_5 $mac0_6
	}

	if {[string match $mac1 "NULL"]!=1} { 
		set mac1_1 [string range $mac1 0 1] 
		set mac1_2 [string range $mac1 2 3] 
		set mac1_3 [string range $mac1 4 5] 
		set mac1_4 [string range $mac1 6 7] 
		set mac1_5 [string range $mac1 8 9] 
		set mac1_6 [string range $mac1 10 11]
		exec -ignorestderr /usr/bin/modify_mac.sh eth1 $mac1_1 $mac1_2 $mac1_3 $mac1_4 $mac1_5 $mac1_6
	}

	if {[string match $mac2 "NULL"]!=1} {
		set mac2_1 [string range $mac2 0 1] 
		set mac2_2 [string range $mac2 2 3]
		set mac2_3 [string range $mac2 4 5] 
		set mac2_4 [string range $mac2 6 7]
		set mac2_5 [string range $mac2 8 9] 
		set mac2_6 [string range $mac2 10 11]
		exec -ignorestderr /usr/bin/modify_mac.sh ath1 $mac2_1 $mac2_2 $mac2_3 $mac2_4 $mac2_5 $mac2_6
	}

	return "OK"
}
#==================================================================

#Start TCP listen
proc Server { channel cliaddr cliport } {
#	puts "Client from $cliaddr:$cliport"
	gets $channel line

	set name [lindex $line 0]
	set passwd [lindex $line 1]
	if {[string match $name $::client_name]==1 && [string match $passwd $::client_passwd]==1 } {
		set cmd [lindex $line 2]
#		puts "Corret: $cmd"

		if {[string match $cmd "device_info"]==1} {
			set res [device_info]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_cpu"]==1} {
			set res [check_cpu]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_ram"]==1} {
			set res [check_ram]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_pci"]==1} {
			set res [check_pci]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_usb"]==1} {
			set res [check_usb]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_uart"]==1} {
			set res [check_uart]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_led"]==1} {
			set res [check_led]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_button"]==1} {
			set res [check_button]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_flash"]==1} {
			set res [check_flash]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_ethernet"]==1} {
			set res [check_ethernet]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "check_wireless"]==1} {
			set res [check_wireless]
			puts $res
			puts $channel $res
		}
		if {[string match $cmd "burn_mac"]==1} {
			set mac0 [lindex $line 3]
			set mac1 [lindex $line 4]
			set mac2 [lindex $line 5]
			set res [burn_mac $mac0 $mac1 $mac2]
			puts $res
			puts $channel $res
		}
	}
	close $channel
}
socket -server Server $::server_port 
vwait forever

