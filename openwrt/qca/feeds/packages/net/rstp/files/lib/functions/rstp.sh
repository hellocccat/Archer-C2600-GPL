#!/bin/sh
# Copyright (c) 2013 The Linux Foundation. All rights reserved.

. /lib/functions.sh

get_linkstatus_check_interval(){
	echo 3
}

get_atheros_header_type(){
	echo 0xfefe
}

get_cpu_mirror_port(){
	. /lib/ipq806x.sh
	board=$(ipq806x_board_name)

	case "$board" in
	*)
		echo "0 6"
		;;
	esac
}

get_switch_config_auto(){
	. /lib/ipq806x.sh
	board=$(ipq806x_board_name)

	case "$board" in
	*)
		echo "=qca eth1 eth1 1 port1"
		echo "=qca eth1 eth1 2 port2"
		echo "=qca eth1 eth1 3 port3"
		echo "=qca eth1 eth1 4 port4"
		echo "=qca eth1 eth0 5 eth0"
		;;
	esac
}

get_switch_port_config(){
	local port_name=$1
	local bridge enable switch switchPortId control_channel data_channel

	config_get enable $port_name enable
	[ "$enable" = "0" ] && return
	enable=0

	config_get bridge $port_name bridge
	config_get enable $bridge enable
	[ "$enable" = "0" ] && return

	config_get switch $port_name switch
	config_get switchPortId $port_name switchPortId
	if [ -n "$switch" ] && [ -n "$switchPortId" ] ; then
		config_get control_channel $switch ifname

		config_get data_channel $port_name ifname
		[ -z "$data_channel" ] && data_channel="$control_channel"

		echo "=qca $control_channel $data_channel $switchPortId $port_name"
	fi
}

get_switch_config_manual(){
	config_foreach get_switch_port_config port
}

get_switch_ports(){
	local autoMode

	config_load "rstp"

	config_get autoMode global autoMode

	if [ "$autoMode" = "1" ] ; then
		get_switch_config_auto
	else
		get_switch_config_manual
	fi
}

func=$1
shift
$func $@
