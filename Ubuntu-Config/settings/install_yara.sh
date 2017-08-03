#!/usr/bin/env bash
# Custom scripts should not be dependent on any items or data from the main install options.
# Scripts should function properly when executed outside the main script.py
# Any required switches should be included in the install_custom.txt file.
# If the script requires human interaction, it probably will hang. You've been warned.
# Note, the main script won't return output.
# This is a sample bash script to test and demonstrate this feature.

# Install dependencies
apt-get install -y -o DPkg::Options::=--force-confold -o Acquire::ForceIPv4=true git python-setuptools python-dev python3-setuptools python3-dev

git clone --recursive https://github.com/VirusTotal/yara-python

cd yara-python
python2 setup.py build
python2 setup.py install
python3 setup.py build
python3 setup.py install
cd ..