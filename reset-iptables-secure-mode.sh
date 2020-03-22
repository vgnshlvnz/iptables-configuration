#!/usr/bin/env sh

IPTABLES=/sbin/iptables


### Flush existing rules and set chain policy setting to DROP
echo "[+] Flushing existing rules and setting chain policy setting to DROP"
$IPTABLES -F
$IPTABLES -F -t nat 
$IPTABLES -X
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP
