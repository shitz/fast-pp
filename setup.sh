#!/bin/bash

# The script sets up two network namespaces (net1 and net2) and connects them
# using a veth pair (veth0 and veth1). It adds 192.168.{10,20}.{1,2}/24
# addresses to the veth interfaces.
# The script needs to be run as root.

# Exit on error
set -e

# Create network namespaces
ip netns add net1
ip netns add net2

# Create veth pair and add them to net1 and net2
ip link add veth0 type veth peer name veth1
ip link set veth0 netns net1
ip link set veth1 netns net2

# Configure addresses
ip netns exec net1 ip addr add 192.168.10.1/24 dev veth0
ip netns exec net1 ip addr add 192.168.20.1/24 dev veth0
ip netns exec net2 ip addr add 192.168.10.2/24 dev veth1
ip netns exec net2 ip addr add 192.168.20.2/24 dev veth1

# Bring up interfaces
ip netns exec net1 ip link set veth0 up
ip netns exec net2 ip link set veth1 up
