#!/usr/bin/env sh


### Variable initialization
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
MODPROBE=/sbin/modprobe
INTNET=192.168.1.0/24
INTF=enp0s25

### Flushing existing rules and setting DROP on chain policies  ###
echo "[+] Flushing existing iptables rules"
$IPTABLES -F
$IPTABLES -F -t nat
$IPTABLES -X
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

### this policy does not handle IPv6 traffic except to drop it.
echo "[+] Disabling IPv6 traffic"
$IP6TABLES -P INPUT DROP
$IP6TABLES -P OUTPUT DROP
$IP6TABLES -P FORWARD DROP

### load connection-tracking modules
$MODPROBE ip_conntrack
$MODPROBE iptable_nat
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_nat_ftp


###### INPUT chain ######
#
echo "[+] Setting up INPUT chain"

### state tracking rules
$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j DROP
$IPTABLES -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### anti-spoofing rules
$IPTABLES -A INPUT -i $INTF ! -s $INTNET -j LOG --log-prefix "SPOOFED PKT "
$IPTABLES -A INPUT -i $INTF ! -s $INTNET -j DROP

### ACCEPT rules
$IPTABLES -A INPUT -i $INTF -p tcp -s $INTNET --dport 22 -m conntrack --ctstate NEW -j ACCEPT
### DHCP rules gotten from https://ixnfo.com/en/iptables-rules-for-dhcp.html
#### DHCPOFFER rule
$IPTABLES -t filter -A INPUT -i $INTF -p udp -s 0.0.0.0 --sport 68 -d 255.255.255.255 --dport 67 -j ACCEPT
$IPTABLES -t filter -A INPUT -i $INTF -p udp -s 0.0.0.0 --sport 67 -d 255.255.255.255 --dport 68 -j ACCEPT
#$IPTABLES -t filter -A INPUT -i $INTF -p udp -s 0.0.0.0 --sport 68 -d 192.168.1.254 --dport 67 -j ACCEPT
#$IPTABLES -t filter -A INPUT -i $INTF -p udp -s $INTNET --sport 68 -d 192.168.1.254 --dport 67 -j ACCEPT
#$IPTABLES -t filter -A INPUT -i $INTF -p udp -s 192.168.1.104 --sport 68 -d 192.168.1.254 --dport 67 -j ACCEPT

### DHCP rules without -t filter
#$IPTABLES -A INPUT -i $INTINF -p udp -s 0.0.0.0 --sport 68 -d 255.255.255.255 --dport 67 -j ACCEPT
#$IPTABLES -A INPUT -i $INTINF -p udp -s 0.0.0.0 --sport 68 -d 192.168.1.254 --dport 67 -j ACCEPT
#$IPTABLES -A INPUT -i $INTINF -p udp -s $INTNET --sport 68 -d 192.168.1.254 --dport 67 -j ACCEPT

$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

### default INPUT LOG rule
$IPTABLES -A INPUT ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### make sure that loopback traffic is accepted
$IPTABLES -A INPUT -i lo -j ACCEPT

###### OUTPUT chain ######
#
echo "[+] Setting up OUTPUT chain"

### state tracking rules
$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID -j DROP
$IPTABLES -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### ACCEPT rules for allowing connections out
$IPTABLES -A OUTPUT -p tcp --dport 21 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 43 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -t filter -A OUTPUT -p udp -s 192.168.1.104 --sport 68 -d 192.168.1.254 --dport 67 -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 4321 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT

### default OUTPUT LOG rule
$IPTABLES -A OUTPUT ! -o lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### make sure that loopback traffic is accepted
$IPTABLES -A OUTPUT -o lo -j ACCEPT

###### FORWARD chain ######
#
echo "[+] Setting up FORWARD chain"

### state tracking rules
$IPTABLES -A FORWARD -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A FORWARD -m conntrack --ctstate INVALID -j DROP
$IPTABLES -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### anti-spoofing rules
$IPTABLES -A FORWARD -i $INTF ! -s $INTNET -j LOG --log-prefix "SPOOFED PKT "
$IPTABLES -A FORWARD -i $INTF ! -s $INTNET -j DROP

### ACCEPT rules
$IPTABLES -A FORWARD -p tcp -i $INTF -s $INTNET --dport 21 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $INTF -s $INTNET --dport 22 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $INTF -s $INTNET --dport 25 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $INTF -s $INTNET --dport 43 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $INTF -s $INTNET --dport 4321 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT

### default LOG rule
$IPTABLES -A FORWARD ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

###### forwarding ######
#
echo "[+] Enabling IP forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward
