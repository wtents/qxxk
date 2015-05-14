#!/usr/bin/wish8.5
set mac0_var ""
set mac1_var ""
set mac2_var ""
frame .area1 -relief sunken
frame .area2 -relief sunken
label .area1.mac0_label -text "MAC0:" 
entry .area1.mac0_entry -textvariable mac0_var
label .area1.mac1_label -text "MAC1:" 
entry .area1.mac1_entry -textvariable mac1_var
label .area1.mac2_label -text "MAC2:" 
entry .area1.mac2_entry -textvariable mac2_var -state disabled
grid .area1.mac0_label -row 1 -column 1 -sticky nsew
grid .area1.mac0_entry -row 1 -column 2 -sticky nsew
grid .area1.mac1_label -row 2 -column 1 -sticky nsew
grid .area1.mac1_entry -row 2 -column 2 -sticky nsew
grid .area1.mac2_label -row 3 -column 1 -sticky nsew
grid .area1.mac2_entry -row 3 -column 2 -sticky nsew

button .area2.write -text "Write MAC address" -command {
if {$mac0_var!=""} {
puts "MAC0:$mac0_var"
} else {
puts "MAC0:NULL"
}
if {$mac1_var!=""} {
puts "MAC1:$mac1_var"
} else {
puts "MAC1:NULL"
}
if {$mac2_var!=""} {
puts "MAC2:$mac2_var"
} else {
puts "MAC2:NULL"
}
exit
}
pack .area2.write -fill x -expand y
pack .area1 .area2 -side top
