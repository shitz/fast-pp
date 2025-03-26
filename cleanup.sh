#!/bin/bash

# Remove network namespaces created by the setup.sh script
# The script needs to be run as root.

# Exit on error
set -e

# Remove network namespaces
ip netns del net1
ip netns del net2
