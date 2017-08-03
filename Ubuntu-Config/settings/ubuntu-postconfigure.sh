#!/usr/bin/env bash
# Enter post install commands here.
# ---------------------------------------------------------------------------------------------------------------------
# Create Custom Folders
mkdir -p /cases

# Create symlinks
ln -s /usr/bin/hashdeep /usr/bin/md5deep