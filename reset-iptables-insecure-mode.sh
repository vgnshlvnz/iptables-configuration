#!/usr/bin/env sh

IPTABLES=/sbin/iptables

echo "[+] Flushing rules and set chain policy to ACCEPT"
$IPTABLES -F
$IPTABLES -F -t nat
$IPTABLES -X
$IPTABLES -P INPUT ACCEPT
$IPTABLES -P OUTPUT ACCEPT
$IPTABLES -P FORWARD ACCEPT
