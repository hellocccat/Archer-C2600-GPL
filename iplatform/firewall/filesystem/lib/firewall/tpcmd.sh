# Copyright (C) 2014 tp-link.net
# Copyright (C) 2014 hu luyao

FW_LIBDIR=${FW_LIBDIR:-/lib/firewall}

. $FW_LIBDIR/fw.sh
. /lib/functions/network.sh
include /lib/network

fw_mount() {
    echo "to do"    
}

fw_unmount() {
    echo "to do"
}

# $1:family
# $2:table
# $3:chain
# $4:key-word
fw_check() {
    local list=$(fw list $1 $2 $3)
    (echo $list | grep -- "$4" > /dev/null 2>&1)&&return 1||return 0    
}

_s_add() {
  
    local fam tab chn tgt pos
    local i
    for i in fam tab chn tgt pos; do
        if [ "$1" -a "$1" != '{' ]; then
            eval "$i='$1'"
            shift
        else
            eval "$i=-"
        fi
    done
    fw_check $fam $tab $chn "-A $chn${2:+ $2} -j $tgt"
    [ x$? != x1 ] && fw add $fam $tab $chn "$tgt" $pos "$@"
}

fw_s_add() {
  
    local fam tab chn tgt pos
    local i
    for i in fam tab chn tgt pos; do
        if [ "$1" -a "$1" != '{' ]; then
            eval "$i='$1'"
            shift
        else
            eval "$i=-"
        fi
    done
    
    if [[ x$fam == x"i" ]]; then
       _s_add "4" $tab $chn "$tgt" $pos "$@"
       _s_add "6" $tab $chn "$tgt" $pos "$@"
    else
        _s_add $fam $tab $chn "$tgt" $pos "$@"
    fi
}

_s_del() {

    local fam tab chn tgt pos
    local i
    for i in fam tab chn tgt pos; do
        if [ "$1" -a "$1" != '{' ]; then
            eval "$i='$1'"
            shift
        else
            eval "$i=-"
        fi
    done

    fw_check $fam $tab $chn "-A $chn${2:+ $2} -j $tgt"
    while [ x$? == x1 ]; do
        fw del $fam $tab $chn "$tgt" $pos "$@"
        fw_check $fam $tab $chn "-A $chn${2:+ $2} -j $tgt"
    done
}

fw_s_del() {
  
    local fam tab chn tgt pos
    local i
    for i in fam tab chn tgt pos; do
        if [ "$1" -a "$1" != '{' ]; then
            eval "$i='$1'"
            shift
        else
            eval "$i=-"
        fi
    done
    
    if [[ x$fam == x"i" ]]; then
       _s_del "4" $tab $chn "$tgt" $pos "$@"
       _s_del "6" $tab $chn "$tgt" $pos "$@"
    else
        _s_del $fam $tab $chn "$tgt" $pos "$@"
    fi
}

fw_block_rt_access() {

    cmd=$1
    shift
    case "$cmd" in
        ip)
            _block_rt_access_ip $1
            exit $?
        ;;
        mac)
            _block_rt_access_mac $1
            exit $?
        ;;
        dev)
            _block_rt_access_dev $1
            exit $?
        ;;
    esac
    
}

# for now ,ipv4 only. by huluyao 20140423
_block_rt_access_ip() {

    ip=$1
    shift
    fw_s_add 4 f block_entry_list DROP { "$rule" }
}


_block_rt_access_mac() {

    local mac=$(echo $1 | tr [a-z] [A-Z])
    shift
    rule="-m mac --mac-source ${mac//-/:}"

    fw_s_add 4 f block_entry_list DROP { "$rule" }
}

_block_rt_access_dev() {

    local dev=$1
    shift
    rule="-m physdev --physdev-in $dev"

    fw_s_add 4 f block_entry_list DROP { "$rule" }

}

fw_unblock_rt_access() {

    cmd=$1
    shift
    case "$cmd" in
        ip)
            _unblock_rt_access_ip $1
            exit $?
        ;;
        mac)
            _unblock_rt_access_mac $1
            exit $?
        ;;
        dev)
            _unblock_rt_access_dev $1
            exit $?
        ;;
    esac
    
}

_unblock_rt_access_ip() {

    ip=$1
    shift
    local rule="-s $ip"
    fw_s_del 4 f block_entry_list DROP { "$rule" }
}

_unblock_rt_access_mac() {

    local mac=$(echo $1 | tr [a-z] [A-Z])
    shift
    rule="-m mac --mac-source ${mac//-/:}"

    fw_s_del 4 f block_entry_list DROP { "$rule" }
   
}

_unblock_rt_access_dev() {

    local dev=$1
    shift
    rule="-m physdev --physdev-in $dev"

    fw_s_del 4 f block_entry_list DROP { "$rule" }

}


fw_load_local_mgnt() {

    local rule="-p tcp -m multiport --ports 80,22,20002"

    fw_s_add 4 f zone_lan local_mgnt 1 { "$rule" }
}

fw_unload_local_mgnt() {

    local rule="-p tcp -m multiport --ports 80,22,20002"

    fw_s_del 4 f zone_lan local_mgnt { "$rule" }
}

fw_add_local_mgnt(){

    local mac=$(echo $1 | tr [a-z] [A-Z])
    local rule="-m mac --mac-source ${mac//-/:}"

    fw_s_add 4 f local_mgnt RETURN 1 { "$rule" }

}

fw_del_local_mgnt(){

    local mac=$(echo $1 | tr [a-z] [A-Z])
    local rule="-m mac --mac-source ${mac//-/:}"

    fw_s_del 4 f local_mgnt RETURN { "$rule" }
}

fw_add_remote_mgnt(){

    local port=$1
    local port_val=$2

    local ip=$3
    local ip_val=$4

    local state
    local rule

    [ x$port != x"port" ] && return
 
    [ x$port_val != x"80" ] && state="-m conntrack --ctstate DNAT"

    if [[ x$ip == x"ip" ]]; then
        ip_val="-s ${ip_val}/32"
        rule="$ip_val -p tcp -m tcp --dport 80${state:+ $state}"
    else
        rule="-p tcp -m tcp --dport 80${state:+ $state}"
    fi

    fw_s_add 4 f input_wan ACCEPT 1 { "$rule" }

    fw flush 4 f lan_remote_mgnt
    local interfaces="internet wan"
    for iface in $interfaces; do
        local wan_ip
        network_get_ipaddr wan_ip "$iface"
        [ -n "$wan_ip" -a "$wan_ip" != "0.0.0.0" ] && {                        
            rule="-d $wan_ip -p tcp -m tcp --dport 80${state:+ $state}"
            fw_s_add 4 f lan_remote_mgnt ACCEPT { "$rule" }
            
            [ x$port_val != x"80" ] && {
                rule="-d $wan_ip -p tcp -m tcp --dport 80"
                fw_s_add 4 f lan_remote_mgnt DROP { "$rule" }
            }
        }
    done
}

fw_del_remote_mgnt(){
    
    local port=$1
    local port_val=$2

    local ip=$3
    local ip_val=$4

    local state
    local rule

    [ x$port != x"port" ] && return
 
    [ x$port_val != x"80" ] && state="-m conntrack --ctstate DNAT"

    if [[ x$ip == x"ip" ]]; then
        ip_val="-s ${ip_val}/32"
        rule="$ip_val -p tcp -m tcp --dport 80${state:+ $state}"
    else
        rule="-p tcp -m tcp --dport 80${state:+ $state}"
    fi

    fw_s_del 4 f input_wan ACCEPT { "$rule" }

    fw flush 4 f lan_remote_mgnt
    local interfaces="internet wan"
    for iface in $interfaces; do
        local wan_ip
        network_get_ipaddr wan_ip "$iface"
        [ -n "$wan_ip" -a "$wan_ip" != "0.0.0.0" ] && {                        
            rule="-d $wan_ip -p tcp -m tcp --dport 80"
            fw_s_add 4 f lan_remote_mgnt DROP { "$rule" }
        }
    done
}

lan_via_inet_ftp_access(){
    local port=$1
    local interfaces="internet wan"

    fw add 4 r ftp_access_lan_to_wan
    fw flush 4 r ftp_access_lan_to_wan
    fw_s_add 4 r zone_lan_notrack ftp_access_lan_to_wan  

    for iface in $interfaces; do
        local wan_ip
        local rule
        network_get_ipaddr wan_ip "$iface"
        [ -n "$wan_ip" -a "$wan_ip" != "0.0.0.0" ] && {                        
            rule="-d $wan_ip -p tcp -m tcp --dport $port"
            fw_s_add 4 r ftp_access_lan_to_wan DROP 1 { "$rule" }
        }
    done    
}

fw_ftp_access(){
    local port=$1
    local mode=$2

    if [[ x$port != x"21" ]]; then
        fw add 4 r ftp_access
        fw_s_add 4 r zone_wan_notrack ftp_access
        local rule="-p tcp -m tcp --dport 21"
        fw_s_add 4 r ftp_access DROP 1 { "$rule" }

        lan_via_inet_ftp_access 21
    fi

    if [ -n "$mode" -a "$mode" == "ftpex_only" ]; then
        local iface="lan"
        fw flush 4 f ftp_access_lan
        network_get_ipaddr lan_ip "$iface"
        [ -n "lan_ip" ] && {
            local rule="-d $lan_ip -p tcp -m tcp --dport 21"
            fw_s_add 4 f ftp_access_lan DROP 1 { "$rule" }
        }
    fi
    
    if [ -n "$mode" -a "$mode" == "all" -o "$mode" == "ftpex_only" ]; then
        local rule="-p tcp -m tcp --dport 21"
        fw_s_add 4 f ftp_access ACCEPT 1 { "$rule" }
    fi
    
    if [ -n "$mode" -a "$mode" == "ftp_only" ]; then
        lan_via_inet_ftp_access 21
    fi
}

fw_ftp_block(){
    local port=$1
    if [[ x$port == x"all" ]]; then
        fw flush 4 f ftp_access
        fw flush 4 f ftp_access_lan
        fw flush 4 r ftp_access
        fw flush 4 r ftp_access_lan_to_wan
        fw_s_del 4 r zone_wan_notrack ftp_access
        fw_s_del 4 r zone_lan_notrack ftp_access_lan_to_wan
        fw del 4 r ftp_access
        fw del 4 r ftp_access_lan_to_wan
    fi
}

fw_setmss(){
    local size=$1
    local rule="-p tcp -m tcp --tcp-flags SYN,RST SYN"
    local target="TCPMSS --set-mss $size"
    fw_s_add 4 m zone_wan_MSSFIX "$target" 1 { "$rule" }

}

fw_unsetmss(){
    fw flush 4 m zone_wan_MSSFIX
}

fw_openvpn_access(){
    local proto=$1
    local port=$2
    local access=$3
    local rule="-p $proto -m $proto --dport $port"
    local homeif="$(uci_get_state firewall core lan_ifname)"
    fw_s_add 4 f zone_wan_vpn_access ACCEPT 1 { "$rule" }
    if [ "$access" == "home" ]; then
        fw_s_add 4 f forward ACCEPT 1 { "-i tun0 -o $homeif" }
        fw_s_add 4 f forwarding_lan ACCEPT { "-i $homeif -o tun0" }
    else
        fw_s_add 4 f forward ACCEPT 1 { "-i tun0" }
        fw_s_add 4 f forwarding_lan ACCEPT { "-o tun0" }
    fi
}
 
fw_openvpn_block(){
    local proto=$1
    local port=$2
    local access=$3
    local rule="-p $proto -m $proto --dport $port"
    local homeif="$(uci_get_state firewall core lan_ifname)"
    fw_s_del 4 f zone_wan_vpn_access ACCEPT 1 { "$rule" }
    if [ "$access" == "home" ]; then
        fw_s_del 4 f forward ACCEPT 1 { "-i tun0 -o $homeif" }
        fw_s_del 4 f forwarding_lan ACCEPT { "-i $homeif -o tun0" }
    else
        fw_s_del 4 f forward ACCEPT 1 { "-i tun0" }
        fw_s_del 4 f forwarding_lan ACCEPT { "-o tun0" }
    fi
}

fw_pptp_access(){
    local rule="-p tcp -m tcp --dport 1723"
    fw_s_add 4 f zone_wan_vpn_access ACCEPT 1 { "$rule" }
    fw_s_add 4 f forward ACCEPT 1 { "-i ppp+" }
    fw_s_add 4 f forwarding_lan ACCEPT { "-o ppp+" }
}

fw_pptp_block(){
    local rule="-p tcp -m tcp --dport 1723"
    fw_s_del 4 f zone_wan_vpn_access ACCEPT 1 { "$rule" }
    fw_s_del 4 f forward ACCEPT 1 { "-i ppp+" }
    fw_s_del 4 f forwarding_lan ACCEPT { "-o ppp+" }
}

tpcmd_post_rule_cb() {

    _add_icmp_rules() { # $chain $list $target
        local _type
        for _type in $2; do
            [ "${_type##!}" == "$_type" ] && \
                fw add 6 f $1 $3 + { -p icmp --icmp-type $_type }
        done
    }
    local input_drop='
        '
    local forward_accept='
        echo-request
        packet-too-big
        destination-unreachable
        time-exceeded
        parameter-problem
        '

    # add ipv6 icmpv6 input rule
    fw add 6 f zone_wan_icmp
    fw add 6 f zone_wan zone_wan_icmp + { -p icmp }
    _add_icmp_rules zone_wan_icmp "$input_drop" DROP
    fw add 6 f zone_wan_icmp ACCEPT +

    # add ipv6 icmpv6 forward rule
    fw add 6 f zone_wan_forward_icmp
    fw add 6 f zone_wan_forward zone_wan_forward_icmp + { -p icmp }
    _add_icmp_rules zone_wan_forward_icmp "$forward_accept" ACCEPT

    # add ipv6 dhcpv6 input rule
    fw add 6 f zone_wan ACCEPT + { -p udp -s fe80::/10 -d fe80::/10 --sport 547 --dport 546 }

    # add for Comcast neighbor-solicitation flood
    fw add 6 m zone_wan_prerouting DROP + { -p icmpv6 --icmpv6-type neighbor-solicitation -d ff02::1:ff00:0/104 }
}

