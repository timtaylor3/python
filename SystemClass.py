#!/usr/bin/env python
"""
This is a class that gets various system items that are used frequently.
Nothing fancy
Use at your own risk
Tested on Ubuntu 14.04 x86_64 and 16.04 x86_64
Python 2.7 and Python 3.5
"""
__author__ = "Tim Taylor"
__email__ = "timtaylor3@yahoo.com"
__version__ = "0.1"
__status__ = "Development"
__credit__ = ["The open source community"]

import ctypes
import platform
import os
if platform.system() != 'Windows':
	from pwd import getpwnam
import subprocess

class SystemClass:
	def __init__(self):
		self.system_os = platform.system()
		self.hostname = platform.node()
		self.system_info = platform.platform( ).split('-')

		if self.system_os == 'Darwin':
			self.darwin_version = self.system_info[1]
			self.arch = self.system_info[2]
			self.processor = self.system_info[3]
			self.kernelBitness = self.system_info[4]
			self.distro = 'Mac'
			self.distro_version = platform.mac_ver()[0]
			if self.distro_version == '10.12.3':
				self.distro_name = 'macOS Sierra'
			elif self.distro_version.split('.')[0] == '10':
				self.distro_name = 'Mac OSX'
			else:
				self.distro_name = 'Unknown Mac OS'
			self.sudo_user = os.getenv('SUDO_USER')
			self.current_user = os.getenv('USER')


		elif self.system_os == 'Linux':
			self.majorKernelVersion = self.system_info[1]
			self.minorKernelVersion = self.system_info[2]
			self.processor= self.system_info[3]
			self.arch = self.system_info[4]
			self.distro = self.system_info[6]
			self.distro_version = self.system_info[7]
			self.distro_name = self.system_info[8]
			self.sudo_user = os.getenv('SUDO_USER')
			self.current_user = os.getenv('USER')


		elif self.system_os == 'Windows':
			self.distro = self.system_info[0]
			self.distro_version = self.system_info[1]
			self.distro_name = ' '. join([self.system_info[0], self.system_info[1]])
			self.build = self.system_info[2]
			self.service_pack =  self.system_info[3]
			self.current_user = os.getlogin()
		else:
			# Need to exit for now
			pass
						

	def getHostname(self):
		return self.hostname

	def getDistro(self):
		return self.distro

	def getDistroName(self):
		return self.distro_name

	def getDistroVersion(self):
		return self.distro_version

	def isLinux(self):
		if self.system_os == "Linux":
			return True
		else:
			return False

	def isMac(self):
		if self.system_os == 'Darwin':
			return True
		else:
			return False

	def isWindows(self):
		if self.system_os == 'Windows':
			return True
		else:
			return False

	def isUbuntu(self):
		if self.distro == 'Ubuntu':
			return True
		else:
			return False

	def getSUDOUser(self):
		if not self.sudo_user:
			return self.sudo_user
		else:
			return self.getCurrentUser()

	def getSUDOUserUID(self):
		if self.sudo_user:
			return getpwnam(self.getSUDOUser()).pw_uid
		else:
			return getpwnam(self.getCurrentUser()).pw_uid

	def getSUDOUserGID(self):
		if self.sudo_user:
			return getpwnam(self.getSUDOUser()).pw_gid
		else:
			return getpwnam(self.getCurrentUser()).pw_uid

	def getCurrentUser(self):
		return self.current_user

	def getCurrentUserUID(self):
		return getpwnam(self.getCurrentUser()).pw_uid

	def IsRootUser(self):
		current_user = ''
		if self.system_os == 'Linux' or self.system_os== 'Mac':
			status = self.run_cmd(['whoami'])
			current_user, err = status.communicate()
			if sys.version_info.major == 3:
				currentUser = current_user.decode('utf-8').strip()
			if 'root' in current_user:
				return True
			else:
				return False
		elif self.system_os == 'Windows':
			current_user = ctypes.windll.shell32.IsUserAnAdmin()
			if (current_user == 1):
				return True
			else:
				return False

	def is64bit(self):
		if self.arch == 'x86_64':
			return True
		else:
			return False

	def run_cmd(self, cmd, inShell=False):
		response = ''
		try:
			response = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=inShell)
			response.wait()

		except CalledProcessError as e:
			response = e.output

		finally:
			return response


if __name__ == "__main__":

	test = SystemClass()

	if test.isMac():
		print(test.getHostname())
		print(test.is64bit())
		print(test.getSUDOUser())
		print(test.getSUDOUserGID())
		print(test.getSUDOUserUID())
		print(test.getCurrentUser())
		print(test.getCurrentUserUID())
		print(test.getDistro())
		print(test.getDistroName())
		print(test.getDistroVersion())
		print(test.IsRootUser())

	elif test.isLinux():
		print(test.getHostname())
		print(test.isUbuntu())
		print(test.is64bit())
		print(test.getSUDOUser())
		print(test.getSUDOUserGID())
		print(test.getSUDOUserUID())

	elif test.isWindows():
		print(test.getHostname())
		print(test.getDistro())
		print(test.getDistroName())
		print(test.getDistroVersion())
		print(test.getCurrentUser())
		print(test.IsRootUser())