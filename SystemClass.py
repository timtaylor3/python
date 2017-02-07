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
            self.kernel_bitness = self.system_info[4]
            self.distro = 'Mac'
            self.distro_version = platform.mac_ver()[0]
            if self.distro_version == '10.12.3':
                self.distro_name = 'macOS Sierra'
            elif self.distro_version.split('.')[0] == '10':
                self.distro_name = 'Mac OSX'
            else:
                self.distro_name = 'Unknown Mac OS'
            self.current_user = os.getenv('USER')
            self.current_user_home_dir = self.get_home_dir(self.current_user)
            self.sudo_user = os.getenv('SUDO_USER')
            self.sudo_user_home_dir = self.get_home_dir(self.current_user)
            if type(self.sudo_user) == None:
                self.sudo_user = ''
                self.sudo_user_home_dir = self.get_home_dir('')

        elif self.system_os == 'Linux':
            self.major_kernel_version = self.system_info[1]
            self.minor_kernel_version = self.system_info[2]
            self.processor= self.system_info[3]
            self.arch = self.system_info[4]
            self.distro = self.system_info[6]
            self.distro_version = self.system_info[7]
            self.distro_name = self.system_info[8]
            self.current_user = os.getenv('USER')
            self.current_user_home_dir = self.get_home_dir(self.current_user)
            self.sudo_user = os.getenv('SUDO_USER')
            if type(self.sudo_user) == None:
                self.sudo_user = ''
                self.sudo_user_home_dir = self.get_home_dir('')

        elif self.system_os == 'Windows':
            self.distro = self.system_info[0]
            self.distro_version = self.system_info[1]
            self.distro_name = ' '. join([self.system_info[0], self.system_info[1]])
            self.build = self.system_info[2]
            self.service_pack =  self.system_info[3]
            self.current_user = os.getlogin()

    def get_hostname(self):
        return self.hostname

    def get_distro(self):
        return self.distro

    def get_distro_name(self):
        return self.distro_name

    def get_distro_version(self):
        return self.distro_version

    def is_linux(self):
        if self.system_os == "Linux":
            return True
        else:
            return False

    def is_mac(self):
        if self.system_os == 'Darwin':
            return True
        else:
            return False

    def is_windows(self):
        if self.system_os == 'Windows':
            return True
        else:
            return False

    def is_ubuntu(self):
        if self.distro == 'Ubuntu':
            return True
        else:
            return False

    def get_build(self):
        if self.is_windows():
            return self.build
        else:
            return 'N/A'

    def get_service_pack(self):
        if self.is_windows():
            return self.service_pack
        else:
            return 'N/A'

    def get_sudo_user(self):
        if not self.sudo_user:
            return self.sudo_user
        else:
            return self.get_current_user()

    def get_sudo_user_id(self):
        if self.sudo_user:
            return getpwnam(self.get_sudo_user()).pw_uid
        else:
            return getpwnam(self.get_current_user()).pw_uid

    def get_sudo_user_gid(self):
        if self.sudo_user:
            return getpwnam(self.get_sudo_user()).pw_gid
        else:
            return getpwnam(self.get_current_user()).pw_gid

    def get_current_user(self):
        return self.current_user

    def get_current_user_id(self):
        return getpwnam(self.get_current_user()).pw_uid

    def get_current_user_gid(self):
        if self.sudo_user:
            return getpwnam(self.get_sudo_user()).pw_gid
        else:
            return getpwnam(self.get_current_user()).pw_gid

    def get_home_dir(self, user):
        if self.is_windows():
            user = ''.join(['~', user])
            return os.path.expanduser(user)
        else:
            return getpwnam(user).pw_dir

    def is_root_user(self):
        current_user = ''
        if self.system_os == 'Linux' or self.system_os == 'Mac':
            status = self.run_cmd(['whoami'])
            current_user, err = status.communicate()
            if sys.version_info.major == 3:
                current_user = current_user.decode('utf-8').strip()
            if 'root' in current_user:
                return True
            else:
                return False
        elif self.system_os == 'Windows':
            current_user = ctypes.windll.shell32.IsUserAnAdmin()
            if current_user == 1:
                return True
            else:
                return False

    def get_script_path(self):
        return os.path.dirname(os.path.abspath(__file__))

    def is_64bit(self):
        if self.arch == 'x86_64':
            return True
        else:
            return False

    def run_cmd(self, cmd):
        response = ''
        try:
            response = subprocess.Popen(cmd, bufsize = -1, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            response.wait()

        except subprocess.CalledProcessError as e:
            response = e.output

        finally:
            return response



if __name__ == "__main__":

    test = SystemClass()

    if test.is_mac():
        print('Is this a Mac: {}'.format(test.is_mac()))
        print('The hostname is: {}'.format(test.get_hostname()))
        print('Is this a 64 bit OS: {}'.format(test.is_64bit()))
        print('If run as sudo, this is the sudo users name: {}'.format(test.get_sudo_user()))
        print('If run as sudo, this is the sudo users GID: {}'.format(test.get_sudo_user_gid()))
        print('If run as sudo, this is the sudo users UID: {}'.format(test.get_sudo_user_id()))
        print('This is the current user name: {}'.format(test.get_current_user()))
        print('This is the current users UID: {}'.format(test.get_current_user_id()))
        print('This is the current users GID: {}'.format(test.get_current_user_gid()))
        print('This is the Distro: {}'.format(test.get_distro()))
        print('This is the Distro Name: {}'.format(test.get_distro_name()))
        print('This is the Distro Version: {}'.format(test.get_distro_version()))
        print('Was this run as root: {}'.format(test.is_root_user()))
        print('This ist the current users home directory: {}'.format(test.get_home_dir(test.get_current_user())))

    elif test.is_linux():
        print('The hostname is: {}'.format(test.get_hostname()))
        print('This is the Distro: {}'.format(test.get_distro()))
        print('Is this Ubuntu: {}'.format(test.is_ubuntu()))
        print('Is this a 64 bit OS: {}'.format(test.is_64bit()))
        print('If run as sudo, this is the sudo users name: {}'.format(test.get_sudo_user()))
        print('If run as sudo, this is the sudo users GID: {}'.format(test.get_sudo_user_gid()))
        print('If run as sudo, this is the sudo users UID: {}'.format(test.get_sudo_user_id()))
        print('This is the current user name: {}'.format(test.get_current_user()))
        print('This is the current users UID: {}'.format(test.get_current_user_id()))
        print('This is the current users GID: {}'.format(test.get_current_user_gid()))
        print('This is the current users home directory: {}'.format(test.get_home_dir(test.get_current_user())))

    elif test.is_windows():
        print('The hostname is: {}'.format(test.get_hostname()))
        print('This is the Distro: {}'.format(test.get_distro()))
        print('This is the Distro Name: {}'.format(test.get_distro_name()))
        print('This is the Distro Version: {}'.format(test.get_distro_version()))
        print('This is the Windows Build: {}'.format(test.get_build()))
        print('This is the current user name: {}'.format(test.get_current_user()))
        print('Was this run as root: {}'.format(test.is_root_user()))
        print('This is the current users home directory: {}'.format(test.get_home_dir(test.get_current_user())))
