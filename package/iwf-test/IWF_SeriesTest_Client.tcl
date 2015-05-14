#!/usr/bin/wish8.5
#1. Pre-definition
set ::user "KenChang"
set ::passwd "IWF300"
set ::serverip 192.168.1.1
#set ::serverip 127.0.0.1
set ::port 9900

set ::DeviceVersion 0.0.0
set ::UART_UTILITY "$env(PWD)/uart-test"
set ::BURNMAC_UTILITY "$env(PWD)/burn_mac.tcl"

set ::var0_0 "Conntecting..."
set ::var0_1 "Unknown"
set ::var0_1c ""
set ::var0_2 "Unknown"

set ::var1 "Unknown"
set ::var2 "Unknown"
set ::var3 "Unknown"
set ::var4 "Unknown"
set ::var5 "Unknown"
set ::var6 "Unknown"
set ::var7 "Unknown"
set ::var8 "Unknown"
set ::var9 "Unknown"
set ::var10 "Unknown"

#2. Check Fonctions Definition
proc check_cpu {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_cpu"
	flush $sock
	gets $sock line
	puts $line
	if {$line!=""} {
		set ::var1_log $line
		return 1
	} else {
		return 0
	}
	close $sock
}
proc check_ram {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_ram"
	flush $sock
	gets $sock line
	puts $line
	if {$line!=""} {
		set ::var2_log $line
		if {[string match $line "OK"]==1} {
			return 1
		} else {
			return 0
		}
	} else {
		return 0
	}
	close $sock
}
proc check_pci {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_pci"
	flush $sock
	gets $sock line
	puts $line
	if {$line!=""} {
		set ::var3_log $line
		return 1
	} else {
		set ::var3_log "Not found"
		return 0
	}
	close $sock
}
proc check_usb {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_usb"
	flush $sock
	gets $sock line
	puts $line
	if {$line!=""} {
		set ::var4_log $line
		return 1
	} else {
		set ::var4_log "Not found"
		return 0
	}
	close $sock
}
proc check_uart {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_uart"
#	flush $sock
#	gets $sock line
	close $sock
	
	set res ""
	set uart_recv_res ""

	puts "1.TEST UART input"
	set uart_recv [lindex [split [exec $::UART_UTILITY input] '\n'] 0]
	puts "uart_recv:$uart_recv"
	set uart_recv_res [lindex [split $uart_recv ':'] 1]
	if {[string match $uart_recv_res "IWFUARTTEST"]==1 } {
#		append res "recv OK "
		return 1
	} else {
#		append res "recv FAIL "
		return 0
	}
	puts $uart_recv_res

#	puts "2.TEST UART output"
#	set uart_trans [exec $::UART_UTILITY output]
#	if {[string match $line "OK"]==1 } {
#		append res "trans OK "
#	} else {
#		append res "trans FAIL"
#	}
#	set ::var5_log $res

#	if {[string match [lindex $res 1] "OK"]==1 && [string match [lindex $res 3] "OK"]==1} {
#		return 1
#	} else {
#		return 0
#	}

}
proc check_led {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_led"
	close $sock
	set res [tk_messageBox -message "LEDs status is OK?" -type yesno]
	if {[string match $res "yes"]==1} {
		return 1
	} else {
		return 0
	}
}
proc check_button {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_button"
	flush $sock
	set res [tk_messageBox -message "Press all test buttons in 10 seconds." -type ok]
	gets $sock line
	if {$line!=""} {
		set ::var7_log $line
		set resetb [lindex [split [lindex $line 0] ':'] 1]
		set wpsb [lindex [split [lindex $line 1] ':'] 1]
		if { $resetb==0 && $wpsb==1 } { 
			return 1
		} else {
			return 0
		}
	} else {
		set ::var7_log "Not detect any infos"
		return 0
	}
	close $sock
}
proc check_flash {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_flash"
	flush $sock
	gets $sock line
	puts $line
	if {$line!=""} {
		set ::var8_log $line
		return 1
	} else {
		return 0
	}
	close $sock
}
proc check_ethernet {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_ethernet"
	close $sock

	set i 0
	set netstats ""
	while { 1 } {
		set res [tk_messageBox -message "After pluging ethernet cable to test hub,please select yes, if finish test, please select no" -type yesno]
		if {[string match $res "no"]==1} { 
			break 
		}
		if {[string match $res "yes"]==1} {
			if {[catch {exec ping -c 3 "$::serverip"} err]} {
				set ::var9_log "Error:$err"
				lappend netstats "port$i:FAIL"
			} else {
				lappend netstats "port$i:PASS"
			}
		}
	incr i
	}

	set ::var9_log "$netstats"
	set check_err [lsearch -glob $netstats "*FAIL"]
	if {$check_err==-1} {
		return 1
	} else {
		return 0
	}
}
proc check_wireless {} {
	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd check_wireless"
	flush $sock
	gets $sock line
	puts $line
	if {$line!=""} {
		set ::var10_log $line
		set wlan0res [lindex $line 1]
		set wlan1res [lindex $line 8]
#		puts "wlan0res=$wlan0res wlan1res=$wlan1res"
#		if {[string match $wlan0res "PASS"]==1 && [string match $wlan1res "PASS"]==1} { }
		if {[string match $wlan0res "PASS"]==1 } {
			return 1
		} else {
			return 0
		}
	} else {
		return 0
	}
	close $sock

}

proc burn_mac {} {
	set res [exec $::BURNMAC_UTILITY]
	puts $res
	set mac_all [split $res '\n']
	set mac0 [lindex [split [lindex $mac_all 0] ':'] 1]
	set mac1 [lindex [split [lindex $mac_all 1] ':'] 1]
	set mac2 [lindex [split [lindex $mac_all 2] ':'] 1]

	set sock [socket $::serverip $::port]
	puts $sock "$::user $::passwd burn_mac $mac0 $mac1 $mac2"

	flush $sock
	gets $sock line
	close $sock
}
#===========================================================
#GUI Definition
label .connect_label -text "Connect TestDevice:"
label .connect_status -textvariable ::var0_0
label .connect_nouse
label .device_version_label -text "DeviceVersion:"
label .device_version_status -textvariable ::var0_1
label .device_version_log -textvariable ::var0_1c
label .device_mac_label -text "DeviceMAC:"
label .device_mac_status -textvariable ::var0_2
label .device_mac_nouse -text "           LOG:           "
label .device_info_nouse -text "                          "

label .check_cpu_status -textvariable ::var1 -background white
label .check_cpu_log -textvariable ::var1_log
label .check_ram_status -textvariable ::var2 -background white
label .check_ram_log -textvariable ::var2_log
label .check_pci_status -textvariable ::var3 -background white
label .check_pci_log -textvariable ::var3_log
label .check_usb_status -textvariable ::var4 -background white
label .check_usb_log -textvariable ::var4_log
label .check_uart_status -textvariable ::var5 -background white
label .check_uart_log -textvariable ::var5_log
label .check_led_status -textvariable ::var6 -background white
label .check_led_log -textvariable ::var6_log
label .check_button_status -textvariable ::var7 -background white
label .check_button_log -textvariable ::var7_log
label .check_flash_status -textvariable ::var8 -background white
label .check_flash_log -textvariable ::var8_log
label .check_ethernet_status -textvariable ::var9 -background white
label .check_ethernet_log -textvariable ::var9_log
label .check_wireless_status -textvariable ::var10 -background white
label .check_wireless_log -textvariable ::var10_log

button .connect_reset -text "Reset all" -command {
	set ::var0_0 "Conntecting..."
	set ::var0_1 "Unknown"
	set ::var0_1c ""
	set ::var0_2 "Unknown"

	set ::var1 "Unknown"; set ::var1_log ""
	.check_cpu_status configure -background white
	set ::var2 "Unknown"; set ::var2_log ""
	.check_ram_status configure -background white
	set ::var3 "Unknown"; set ::var3_log ""
	.check_pci_status configure -background white
	set ::var4 "Unknown"; set ::var4_log ""
	.check_usb_status configure -background white
	set ::var5 "Unknown"; set ::var5_log ""
	.check_uart_status configure -background white
	set ::var6 "Unknown"; set ::var6_log ""
	.check_led_status configure -background white
	set ::var7 "Unknown"; set ::var7_log ""
	.check_button_status configure -background white
	set ::var8 "Unknown"; set ::var8_log ""
	.check_flash_status configure -background white
	set ::var9 "Unknown"; set ::var9_log ""
	.check_ethernet_status configure -background white
	set ::var10 "Unknown"; set ::var10_log ""
	.check_wireless_status configure -background white

	init
}

button .burn_mac_label -text "Write MAC address" -command {
	set res [burn_mac]
}

button .auto_test_label -text "Auto TEST Fonctions" -command {
	.check_cpu_label invoke
	.check_ram_label invoke
	.check_pci_label invoke
	.check_usb_label invoke
	.check_flash_label invoke
	.check_wireless_label invoke
}

button .check_cpu_label -text "Check CPU:" -command {
	set res [check_cpu]
	if { $res==1 } {
		set var1 "PASS"
		.check_cpu_status configure -background green
	} else {
		set var1 "FAIL"
		.check_cpu_status configure -background red
	}
}
button .check_ram_label -text "Check DDR2 RAM:" -command {
	set res [check_ram]
	if { $res==1 } {
		set var2 "PASS"
		.check_ram_status configure -background green
	} else {
		set var2 "FAIL"
		.check_ram_status configure -background red
	}
}
button .check_pci_label -text "Check PCI interface:" -command {
	set res [check_pci]
	if { $res==1 } {
		set var3 "PASS"
		.check_pci_status configure -background green
	} else {
		set var3 "FAIL"
		.check_pci_status configure -background red
	}
}
button .check_usb_label -text "Check USB interface:" -command {
	set res [check_usb]
	if { $res==1 } {
		set var4 "PASS"
		.check_usb_status configure -background green
	} else {
		set var4 "FAIL"
		.check_usb_status configure -background red
	}
}
button .check_uart_label -text "Check UART:" -command {
	set res [check_uart]
	if { $res==1 } {
		set var5 "PASS"
		.check_uart_status configure -background green
	} else {
		set var5 "FAIL"
		.check_uart_status configure -background red
	}
}
button .check_led_label -text "Check LED:" -command {
	set res [check_led]
	if { $res==1 } {
		set var6 "PASS"
		.check_led_status configure -background green
	} else {
		set var6 "FAIL"
		.check_led_status configure -background red
	}
}
button .check_button_label -text "Check Buttons:" -command {
	set res [check_button]
	if { $res==1 } {
		set var7 "PASS"
		.check_button_status configure -background green
	} else {
		set var7 "FAIL"
		.check_button_status configure -background red
	}
}
button .check_flash_label -text "Check NAND flash:" -command {
	set res [check_flash]
	if { $res==1 } {
		set var8 "PASS"
		.check_flash_status configure -background green
	} else {
		set var8 "FAIL"
		.check_flash_status configure -background red
	}
}
button .check_ethernet_label -text "Check Ethernet:" -command {
	set res [check_ethernet]
	if { $res==1 } {
		set var9 "PASS"
		.check_ethernet_status configure -background green
	} else {
		set var9 "FAIL"
		.check_ethernet_status configure -background red
	}
}
button .check_wireless_label -text "Check Wireless:" -command {
	set res [check_wireless]
	if { $res==1 } {
		set var10 "PASS"
		.check_wireless_status configure -background green
	} else {
		set var10 "FAIL"
		.check_wireless_status configure -background red
	}
}

grid .connect_label -row 1 -column 1 -sticky nsew
grid .connect_status -row 1 -column 2 -sticky nsew
#grid .connect_nouse -row 1 -column 3 -sticky nsew
grid .connect_reset -row 1 -column 3 -sticky nsew
grid .device_version_label -row 2 -column 1 -sticky nsew
grid .device_version_status -row 2 -column 2 -sticky nsew
grid .device_version_log -row 2 -column 3 -sticky nsew
grid .device_mac_label -row 3 -column 1 -sticky nsew
grid .device_mac_status -row 3 -column 2 -sticky nsew
grid .device_mac_nouse -row 3 -column 3 -sticky nsew
grid .burn_mac_label -row 4 -column 1 -sticky nsew
grid .auto_test_label -row 4 -column 2 -sticky nsew
grid .device_info_nouse -row 4 -column 3 -sticky nsew
grid .check_cpu_label -row 5 -column 1 -sticky nsew
grid .check_cpu_status -row 5 -column 2 -sticky nsew
grid .check_cpu_log -row 5 -column 3 -sticky nsew
grid .check_ram_label -row 6 -column 1 -sticky nsew
grid .check_ram_status -row 6 -column 2 -sticky nsew
grid .check_ram_log -row 6 -column 3 -sticky nsew
grid .check_pci_label -row 7 -column 1 -sticky nsew
grid .check_pci_status -row 7 -column 2 -sticky nsew
grid .check_pci_log -row 7 -column 3 -sticky nsew
grid .check_usb_label -row 8 -column 1 -sticky nsew
grid .check_usb_status -row 8 -column 2 -sticky nsew
grid .check_usb_log -row 8 -column 3 -sticky nsew
#grid .check_uart_label -row 9 -column 1 -sticky nsew
#grid .check_uart_status -row 9 -column 2 -sticky nsew
#grid .check_uart_log -row 9 -column 3 -sticky nsew
grid .check_led_label -row 10 -column 1 -sticky nsew
grid .check_led_status -row 10 -column 2 -sticky nsew
grid .check_led_log -row 10 -column 3 -sticky nsew
grid .check_button_label -row 11 -column 1 -sticky nsew
grid .check_button_status -row 11 -column 2 -sticky nsew
grid .check_button_log -row 11 -column 3 -sticky nsew
grid .check_flash_label -row 12 -column 1 -sticky nsew
grid .check_flash_status -row 12 -column 2 -sticky nsew
grid .check_flash_log -row 12 -column 3 -sticky nsew
grid .check_ethernet_label -row 13 -column 1 -sticky nsew
grid .check_ethernet_status -row 13 -column 2 -sticky nsew
grid .check_ethernet_log -row 13 -column 3 -sticky nsew
grid .check_wireless_label -row 14 -column 1 -sticky nsew
grid .check_wireless_status -row 14 -column 2 -sticky nsew
grid .check_wireless_log -row 14 -column 3 -sticky nsew

proc init { } {
	if {[catch {set sock [socket $::serverip $::port]} err]} {
		set ::var0_0 "Error:$err"
	} else {
		set ::var0_0 "Connected."
		puts $sock "$::user $::passwd device_info"
		flush $sock
		gets $sock device_info
		puts $device_info

		set version [lindex $device_info 0] 
		set version_main [lindex [split [lindex [split $version '.'] 0] ':'] 1]
		set version_second [lindex [split $version '.'] 1]
		set version_third [lindex [split $version '.'] 2]

		set defversion_main [lindex [split $::DeviceVersion '.'] 0]
		set defversion_second [lindex [split $::DeviceVersion '.'] 1]
		set defversion_third [lindex [split $::DeviceVersion '.'] 2]

		if { $version_main==$defversion_main && $version_second==$defversion_second && [string match "$version_third" "$defversion_third"]==1} {
			set ::var0_1c "Version is already lastest."
		} else { 
			set ::var0_1c "Version maybe too old."
		}

		set mac	[lrange $device_info 1 end]
		set ::var0_1 [lindex [split $version ':'] 1]
		set ::var0_2 "$mac"
		close $sock
	}
}
init
