#!/bin/bash

# Set default chain policies that will trigger
# when a packet reaches the end of the rule chain.
# DROP Everything. Its all trash traffic.
# NOTE: flushing (-F) might clear docker and other service-specific
# rules that are neccessary for the services to capture any traffic.
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Drop fragmented packets
iptables -A INPUT -f -j DROP

# Drop XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Drop NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Drop all Invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# Drop ICMP (Ping) packets
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP

# Do not respond to pings
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP

# Drop Spoofed packets
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A OUTPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A OUTPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A OUTPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A OUTPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A OUTPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A OUTPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A OUTPUT -d 255.255.255.255 -j DROP

# If TCP (even when disabled), first packet has to be SYN
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Drop Various Attacks
iptables -A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --destination-port 8080 -j DROP
iptables -t mangle -A PREROUTING -p tcp ! --syn -m state --state NEW -j DROP

# Block Packets used by Port-Scans
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Log Port-Scan Attempts
iptables -A INPUT -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A FORWARD -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A INPUT -m recent --name portscan --set -j DROP
iptables -A FORWARD -m recent --name portscan --set -j DROP

# Lock-out systems that attempted a port-scan (lock lasts a day)
#iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
#iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
#iptables -A INPUT -m recent --name portscan --remove
#iptables -A FORWARD -m recent --name portscan --remove

# Accept on localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Accept established sessions to receive traffic
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept DNS Normal Queries
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
# Accept DNS Long Queries
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# TEMPLATE: Adding a service NEEDED
#iptables -A OUTPUT -p tcp --dport PORT -j ACCEPT

# TEMPLATE: Accept a service that is PROVIDED
#iptables -A INPUT -p tcp --dport PORT -j ACCEPT

# Accept SSH (into this machine)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
# Accept SSH (out to others)
#iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Drop excessive RST Packets to avoid Smurf-Attacks
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# DROP SYN-FLOOD PACKETS
iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 50/second --limit-burst 50 -j ACCEPT
