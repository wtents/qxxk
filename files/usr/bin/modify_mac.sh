#!/bin/sh

MTD5_OLD="/tmp/old_mtd5"
MTD5_NEW="/tmp/new_mtd5"

interface=$1
mac0=$2
mac1=$3
mac2=$4
mac3=$5
mac4=$6
mac5=$7

#reset
#cat /dev/null > /dev/mtdblock5
#cat art.backup > /dev/mtdblock5

debug(){
	echo "--------------------------------"
	echo "[debug]eth0,1:(old)"
	hexdump -C ${MTD5_OLD} |grep "00000000"
	echo "[debug]eth0,1:(new)"
	hexdump -C ${MTD5_NEW} |grep "00000000"
	echo "--------------------------------"
	echo "[debug]wan0:(old)"
	hexdump -C ${MTD5_OLD} |grep "00001000"
	echo "[debug]wan0:(new)"
	hexdump -C ${MTD5_NEW} |grep "00001000"
}

write_to_flash(){
	echo "5.clean mtd5"
	cat /dev/null > /dev/mtdblock5

	echo "6.write new data to /dev/mtd5"
	cat ${MTD5_NEW} > /dev/mtdblock5
}

#wlan0 mac:0x00001002 ~ 0x00001007
new_wlan0_mtd5_generate(){

	echo "3.cut mtd5 from 0-4098"
	dd if=${MTD5_OLD} of=/tmp/wlan0_0_4098 bs=1 count=4098
	echo "3.cut mtd5 from 4104-65535"
	dd if=${MTD5_OLD} of=/tmp/wlan0_4104_65535 bs=1 skip=4104 count=61432

	echo "4.merge a new mtd5 with wlan0_0_4098 + wlan0 mac + 4104-65535"
	cat /dev/null 		>  ${MTD5_NEW}
	cat /tmp/wlan0_0_4098 	>> ${MTD5_NEW}
	cat /tmp/6bytes_mac 	>> ${MTD5_NEW}	#wlan0 mac
	cat /tmp/wlan0_4104_65535	>> ${MTD5_NEW}

	write_to_flash
	debug
}
#eth1 mac:0x00000006 ~ 0x0000000b
new_eth1_mtd5_generate(){

	echo "3.cut mtd5 from 0-5"
	dd if=${MTD5_OLD} of=/tmp/eth1_0_5 bs=1 count=6
	echo "3.cut mtd5 from 13-65535"
	dd if=${MTD5_OLD} of=/tmp/eth1_13_65535 bs=1 skip=12 count=65524

	echo "4.merge a new mtd5 with eth1_0_5 + eth1 mac + eth1_13_65535"
	cat /dev/null 		>  ${MTD5_NEW}
	cat /tmp/eth1_0_5 	>> ${MTD5_NEW}
	cat /tmp/6bytes_mac 	>> ${MTD5_NEW}	#eth1 mac
	cat /tmp/eth1_13_65535	>> ${MTD5_NEW}

	write_to_flash
	debug
}
#eth0 mac:0x00000000 ~ 0x00000005
new_eth0_mtd5_generate(){

	echo "3.cut mtd5 from eth0_7_65536"
	dd if=${MTD5_OLD} of=/tmp/eth0_7_65536 bs=1 skip=6 count=65530

	echo "4.merge a new mtd5 with eth1 mac + eth0_7_65536"
	cat /dev/null 		>  ${MTD5_NEW}
	cat /tmp/6bytes_mac 	>> ${MTD5_NEW}	#eth0 mac
	cat /tmp/eth0_7_65536 	>> ${MTD5_NEW}	#7~65536

	write_to_flash
	debug
}

wlan0_chk_write_to_flash(){
	echo $1:$2:$3:$4:$5:$6 | egrep "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
	if [ $? = 0 ]; then
		echo "correct mac address"
		#create a eth1 mac 6 bytes bin file
		/usr/bin/mips_mac_write $interface $mac0 $mac1 $mac2 $mac3 $mac4 $mac5 $mac6
		new_wlan0_mtd5_generate
	else
		echo "Invalid mac address"
		return
	fi
}

eth1_chk_write_to_flash(){
	echo $1:$2:$3:$4:$5:$6 | egrep "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
	if [ $? = 0 ]; then
		echo "correct mac address"
		#create a eth1 mac 6 bytes bin file
		/usr/bin/mips_mac_write $interface $mac0 $mac1 $mac2 $mac3 $mac4 $mac5 $mac6
		new_eth1_mtd5_generate
	else
		echo "Invalid mac address"
		return
	fi
}
eth0_chk_write_to_flash(){
	echo $1:$2:$3:$4:$5:$6 | egrep "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
	if [ $? = 0 ]; then
		echo "correct mac address"
		#create a eth0 mac 6 bytes bin file
		/usr/bin/mips_mac_write $interface $mac0 $mac1 $mac2 $mac3 $mac4 $mac5 $mac6
		new_eth0_mtd5_generate
	else
		echo "Invalid mac address"
		return
	fi
}

if [ "$1" = "eth0" ]; then
	echo "1.dump mtd5 from flash"
	cat /dev/mtdblock5 > ${MTD5_OLD}
	echo "2.create 6bytes mac binary hex file"
	eth0_chk_write_to_flash $2 $3 $4 $5 $6 $7
elif [ "$1" = "eth1" ]; then
	echo "1.dump mtd5 from flash"
	cat /dev/mtdblock5 > ${MTD5_OLD}
	echo "2.create 6bytes mac binary hex file"
	eth1_chk_write_to_flash $2 $3 $4 $5 $6 $7
elif [ "$1" = "wlan0" ]; then
	echo "1.dump mtd5 from flash"
	cat /dev/mtdblock5 > ${MTD5_OLD}
	echo "2.create 6bytes mac binary hex file"
	wlan0_chk_write_to_flash $2 $3 $4 $5 $6 $7
else
	echo "Usage:[eth0 00 10 f3 3f b5 24]"
	echo "Usage:[eth1 00 10 f3 3f b5 25]"
	echo "Usage:[wlan0 00 10 f3 3f b5 26]"
fi
