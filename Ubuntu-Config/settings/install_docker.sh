#!/usr/bin/env bash
# Custom scripts should not be dependent on any items or data from the main install options.
# Scripts should function properly when executed outside the main script.py
# Any required switches should be included in the install_other file.
# If the script requires human interaction, it propably will hang. You've been warned.
# Note, the main script won't return output.  The echo commands are for standalone testing.
# This is a sample bash script to test and demonstrate this feature.

# REF: https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-16-04

apt-get update
apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
apt-add-repository 'deb https://apt.dockerproject.org/repo ubuntu-xenial main'
apt-get update
apt-cache policy docker-engine
apt-get install -y docker-engine