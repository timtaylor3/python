#!/usr/bin/env python
"""
This is a class that gets various system items that are used frequently.
Nothing fancy
Use at your own risk
Tested on Ubuntu 16.04 x86_64
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
			self.sudo_user_home_dir = self.get_home_dir(self.current_user)
			self.current_user = os.getenv('USER')
			self.current_user_home_dir = self.get_home_dir(self.current_user)

		elif self.system_os == 'Linux':
			self.majorKernelVersion = self.system_info[1]
			self.minorKernelVersion = self.system_info[2]
			self.processor= self.system_info[3]
			self.arch = self.system_info[4]
			self.distro = self.system_info[6]
			self.distro_version = self.system_info[7]
			self.distro_name = self.system_info[8]
			self.sudo_user = os.getenv('SUDO_USER')
			self.sudo_user_home_dir = self.get_home_dir(self.sudo_user)
			self.current_user = os.getenv('USER')
			self.current_user_home_dir = self.get_home_dir(self.current_user)


		elif self.system_os == 'Windows':
			self.distro = self.system_info[0]
			self.distro_version = self.system_info[1]
			self.distro_name = ' '. join([self.system_info[0], self.system_info[1]])
			self.build = self.system_info[2]
			self.service_pack =  self.system_info[3]
			self.current_user = os.getlogin()

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

	def getBuild(self):
		if self.isWindows():
			return self.build
		else:
			return 'N/A'

	def getServicePack(self):
		if self.isWindows():
			return self.service_pack
		else:
			return 'N/A'

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
			return getpwnam(self.getCurrentUser()).pw_gid

	def getCurrentUser(self):
		return self.current_user

	def getCurrentUserUID(self):
		return getpwnam(self.getCurrentUser()).pw_uid

	def getCurrentUserGID(self):
		if self.sudo_user:
			return getpwnam(self.getSUDOUser()).pw_gid
		else:
			return getpwnam(self.getCurrentUser()).pw_gid

	def get_home_dir(self, user):
		return os.path.expanduser('~')

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
		print('Is this a Mac: {}'.format(test.isMac()))
		print('The hostname is: {}'.format(test.getHostname()))
		print('Is this a 64 bit OS: {}'.format(test.is64bit()))
		print('If run as sudo, this is the sudo users name: {}'.format(test.getSUDOUser()))
		print('If run as sudo, this is the sudo users GID: {}'.format(test.getSUDOUserGID()))
		print('If run as sudo, this is the sudo users UID: {}'.format(test.getSUDOUserUID()))
		print('This is the current user name: {}'.format(test.getCurrentUser()))
		print('This is the current users UID: {}'.format(test.getCurrentUserUID()))
		print('This is the current users GID: {}'.format(test.getCurrentUserGID()))
		print('This is the Distro: {}'.format(test.getDistro()))
		print('This is the Distro Name: {}'.format(test.getDistroName()))
		print('This is the Distro Version: {}'.format(test.getDistroVersion()))
		print('Was this run as root: {}'.format(test.IsRootUser()))
		print('This ist the current users home directory: {}'.format(test.get_home_dir(test.getCurrentUser())))

	elif test.isLinux():
		print('The hostname is: {}'.format(test.getHostname()))
		print('This is the Distro: {}'.format(test.getDistro()))
		print('Is this Ubuntu: {}'.format(test.isUbuntu()))
		print('Is this a 64 bit OS: {}'.format(test.is64bit()))
		print('If run as sudo, this is the sudo users name: {}'.format(test.getSUDOUser()))
		print('If run as sudo, this is the sudo users GID: {}'.format(test.getSUDOUserGID()))
		print('If run as sudo, this is the sudo users UID: {}'.format(test.getSUDOUserUID()))
		print('This is the current user name: {}'.format(test.getCurrentUser()))
		print('This is the current users UID: {}'.format(test.getCurrentUserUID()))
		print('This is the current users GID: {}'.format(test.getCurrentUserGID()))
		print('This ist the current users home directory: {}'.format(test.get_home_dir(test.getCurrentUser())))

	elif test.isWindows():
		print('The hostname is: {}'.format(test.getHostname()))
		print('This is the Distro: {}'.format(test.getDistro()))
		print('This is the Distro Name: {}'.format(test.getDistroName()))
		print('This is the Distro Version: {}'.format(test.getDistroVersion()))
		print('This is the Windows Build: {}'.format(test.getBuild()))
		print('This is the current user name: {}'.format(test.getCurrentUser()))
		print('Was this run as root: {}'.format(test.IsRootUser()))
		print('This ist the current users home directory: {}'.format(test.get_home_dir(test.getCurrentUser())))
