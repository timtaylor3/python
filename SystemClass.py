#!/usr/bin/env python
"""
This is a class that gets various system items that are used frequently.
Nothing fancy
Use at your own risk
Tested on Ubuntu 14.04 x86_64 and 16.04 x86_64
Python 2.7 and Python 3.5
TODO:  Add other linux distros
"""
__author__ = "Tim Taylor"
__email__ = "timtaylor3@yahoo.com"
__version__ = "0.1"
__status__ = "Development"
__credit__ = ["The open source community"]

import platform
import os
from pwd import getpwnam

class SystemClass:
	def __init__(self):
		self.hostname = platform.node()
		self.linux_info = platform.platform( ).split( "-" )
		self.kernelOS = self.linux_info[0]
		self.majorKernelVersion = self.linux_info[1]
		self.minorKernelVersion = self.linux_info[2]
		self.kernelType = self.linux_info[3]
		self.kernelBitness = self.linux_info[4]
		self.distro = self.linux_info[6]
		self.distro_version = self.linux_info[7]
		self.distro_name = self.linux_info[8]
		self.sudo_user = os.getenv('SUDO_USER')
		self.current_user = os.getenv('USER')

	def getHostname(self):
		return self.hostname

	def getDistro(self):
		return self.distro

	def getDistroName(self):
		return self.linux_info[8]

	def getDistroVersion(self):
		return self.linux_info[7]

	def isLinux(self):
		if "Linux" in self.linux_info[0]:
			return True
		else:
			return False

	def isUbuntu(self):
		if self.distro == 'Ubuntu':
			return True
		else:
			return False

	def getSUDOUser(self):
		# If the user isn't 'sudo', this function breaks the script with returning something valid
		if not self.sudo_user:
			return self.sudo_user
		else:
			return self.getCurrentUser()

	def getSUDOUserUID(self):
		return getpwnam(self.getSUDOUser()).pw_uid

	def getSUDOUserGID(self):
		return getpwnam(self.getSUDOUser()).pw_gid

	def getCurrentUser(self):
		return self.current_user

	def getCurrentUserUID(self):
		return getpwnam(self.getCurrentUser()).pw_uid

	def IsRootUser(self):
		if self.isLinux() == True:
			if 'root' in self.current_user:
				return True
			else:
				return False
		else:
			return False

	def is64bit(self):
		if self.kernelBitness == 'x86_64':
			return True
		else:
			return False

if __name__ == "__main__":
	
	test = SystemClass()
	print(test.getHostname())
	print(test.isLinux())
	print(test.isUbuntu())
	print(test.is64bit())
	print(test.IsRootUser())
	print(test.getCurrentUser())
	print(test.getCurrentUserUID())
	print(test.getSUDOUser())
	print(test.getSUDOUserGID())
	print(test.getSUDOUserUID())
	print(test.getDistro())
	print(test.getDistroName())
	print(test.getDistroVersion())
