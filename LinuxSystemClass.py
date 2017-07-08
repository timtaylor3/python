
#!/usr/bin/env python
"""
This is a class that gets various Linux system items that are used frequently.
Use at your own risk
Tested on CentOS 7 using Python 2.7
"""
__author__ = "Tim Taylor"
__email__ = "timtaylor3@yahoo.com"
__version__ = "0.1"
__status__ = "Development"

import os
import platform
import sys
from pwd import getpwnam

class LinuxSystemClass:
    def __init__(self):
        self.os_release = {}
        self.system_os = platform.system()
        self.hostname = platform.node()
        self.system_info = platform.platform( ).split('-')

        if self.system_os == 'Linux':
            self.os_release = self.parse_os_release('/etc/os-release')
            self.major_kernel_version = self.system_info[1]
            self.minor_kernel_version = self.system_info[2]
            self.processor = self.system_info[3]
            self.pretty_name  = self.os_release.get('PRETTY_NAME')
            self.distro_name = self.os_release.get('ID')
            self.distro = self.os_release.get('ID')
            self.distro_version = self.os_release.get('VERSION_ID')
            self.current_user = os.getenv('USER')
            self.current_user_home_dir = self.get_home_dir(self.current_user)
            self.sudo_user = os.getenv('SUDO_USER')
            if type(self.sudo_user) == None:
                self.sudo_user = ''
                self.sudo_user_home_dir = self.get_home_dir('')
        else:
            sys.exit(1)

    def parse_os_release(self, release_file):
        os_release = {}
        with open(release_file) as f:
            for line in f:
                if line.strip('\n') != "":
                    k,v = line.rstrip('\n').split("=")
                    os_release[k] = v.strip('"')
        return os_release

    def get_hostname(self):
        return self.hostname

    def get_distro(self):
        return self.distro

    def get_distro_name(self):
        return self.distro_name

    def get_distro_version(self):
        return self.distro_version

    def is_linux(self):
        return self.system_os == "Linux"

    def is_ubuntu(self):
        return self.distro.upper() == 'UBUNTU'

    def is_centos(self):
        return self.distro.upper() == 'CENTOS'

    def get_sudo_user(self):
        if self.sudo_user:
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
        return getpwnam(user).pw_dir

    def is_root_user(self):
       return self.get_current_user() == 'root'

    def get_script_path(self):
        return os.path.dirname(os.path.abspath(__file__))

    def is_64bit(self):
        return self.processor == 'x86_64'

    def get_major_kernel_version(self):
        return self.major_kernel_version

    def get_minor_kernel_version(self):
        return self.minor_kernel_version
    
    def get_processor_type(self):
        return self.processor

if __name__ == "__main__":

    test = LinuxSystemClass()

    print('The hostname is: {}'.format(test.get_hostname()))
    print('This is the Distro: {}'.format(test.get_distro()))
    print('Is this Ubuntu: {}'.format(test.is_ubuntu()))
    print('Is this CentOS: {}'.format(test.is_centos()))
    print('Is this a 64 bit OS: {}'.format(test.is_64bit()))
    print('Processor: {}'.format(test.get_processor_type()))
    print('Major Kernel Version: {}'.format(test.get_major_kernel_version()))
    print('Minor Kernel Version: {}'.format(test.get_minor_kernel_version()))
    print('Is the root the current user: {}'.format(test.is_root_user()))
    print('If run as sudo, this is the sudo users name: {}'.format(test.get_sudo_user()))
    print('If run as sudo, this is the sudo users GID: {}'.format(test.get_sudo_user_gid()))
    print('If run as sudo, this is the sudo users UID: {}'.format(test.get_sudo_user_id()))
    print('This is the current user name: {}'.format(test.get_current_user()))
    print('This is the current users UID: {}'.format(test.get_current_user_id()))
    print('This is the current users GID: {}'.format(test.get_current_user_gid()))
    print('This is the current users home directory: {}'.format(test.get_home_dir(test.get_current_user())))
