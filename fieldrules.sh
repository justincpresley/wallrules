#!/bin/bash

# This script is like a field, anything and everything
# is getting past it.

# Set default chain policies
iptables -F
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
