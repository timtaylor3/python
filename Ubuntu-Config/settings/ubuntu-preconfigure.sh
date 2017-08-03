#!/usr/bin/env bash
# Enter Custom Ubuntu commands here, such as installing repos and pre-seeding as shown below.
# Command here are executed one at a time through python.
# It is recommended to comment out lines not being used.
# ---------------------------------------------------------------------------------------------------------------------
# Enter all Repos commands here.  Comment out lines with #
# Because some repos require key's to be added, put the valid bash command line here for every repo command.
# Repos can be added as a pre-seed

# SIFT Repos
add-apt-repository -y ppa:sift/stable
add-apt-repository -y ppa:sift/dev

# GIFT Repo
add-apt-repository -y ppa:gift/stable

# ---------------------------------------------------------------------------------------------------------------------
# https://help.ubuntu.com/16.04/installation-guide/example-preseed.txt
# pre-seed installs commands
# install debconf-utils, then debconf-get-selections | grep XXX to figure out pre-seed command line
# this doesn't always work.  YMMV

# pre-seed nbd-client
# echo "nbd-client nbd-client/killall boolean true" | debconf-set-selections

# pre-seed for wireshark -> True should indicate normal user can capture network traffic - Need to test.
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

# pre-seed core fonts for wine
# echo "ttf-mscorefonts-installer   msttcorefonts/accepted-mscorefonts-eula boolean true" | debconf-set-selections
# echo "ttf-mscorefonts-installer   msttcorefonts/present-mscorefonts-eula note" | debconf-set-selections
# echo "ttf-mscorefonts-installer   msttcorefonts/error-mscorefonts-eula error" | debconf-set-selections