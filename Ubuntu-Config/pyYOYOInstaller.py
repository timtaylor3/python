#!/usr/bin/env python
########################################################################################################################
# This script was designed to be a framework to quickly build an Ubuntu OS from a default install.
# Before adding new packages,
#       create a new OS run the old script.
#       Add the purposed changes manually.
#       Run apt-get update and apt-get upgrade to ensure no breakage
#       For custom install scripts, ensure it will run standalone with no user intervention.
# Supporting Config Files:
#   ubuntu-preconfigure.txt  -> Put all commands that need to be run before package install here, ie repos, pre-seed, etc
#   ubuntu-postconfigure.txt -> Put all commands that need to be run after everything has been completed here.
#   packages-ubuntu.txt      -> Put the package name of packages to install here.
#   modules-python.txt       -> Put all of the python modules that can be pip installed here (Python 2 and 3)
#   install_custom.txt       -> Put the script name of all scripts that need to be run to complete the installation.
# Tested on Ubuntu 16.04 using Python 2.7 and Python 3.5
# Credit:  This script was inspired by the SIFT bootstrap install script found here: https://github.com/sans-dfir/sift-bootstrap
# TODO Roadmap
# TODO: v2 - Add another column in the ubuntu package and python modules lists to support tracking of repo
# TODO: v2 - Add another column in custom scripts to document purpose.
# TODO: v2 - Add std_out to the a log file so that 'tail' can be used to monitor the progress of long running installations.
# TODO: v2 - Add a failed install test when returncode ==0 but install fails.
# TODO: v3 - Allow for calling an interactive bash script, at least std_out should work
# TODO: vEventually - Code cleanup for the pep 8 nazi's.
# TODO: vEventually, port the script to handle ubuntu and centos, or just make a centos version
# Known Issue:  
########################################################################################################################
__author__ = "Tim Taylor"
__email__ = "timtaylor3@yahoo.com"
__version__ = "1.0 beta"
__status__ = "Active Development"
__credit__ = ["https://github.com/sans-dfir/sift-bootstrap", "The Open Source Community"]

import argparse
import ctypes
import logging
import platform
import os
import shlex
import subprocess
import sys
from pwd import getpwnam


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
            self.sudo_user = os.getenv('SUDO_USER')
            self.sudo_user_home_dir = self.get_home_dir( self.sudo_user)
            self.current_user = os.getenv('USER')
            self.current_user_home_dir = self.get_home_dir(self.current_user)

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
            return self.current_user

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
            u = ''.join(['~', user])
            return os.path.expanduser(u)
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


class InstallAppClass:
    def __init__(self, opts):
        self.system_check = SystemClass()
        is_ubuntu = self.system_check.is_ubuntu()
        is_root = self.system_check.is_root_user()

        if is_ubuntu and is_root:
            current_user = self.system_check.get_current_user()
            sudo_user = self.system_check.get_sudo_user()
            self.home_dir = self.system_check.get_home_dir(sudo_user)
            self.script_name = os.path.basename(__file__)
            self.script_dir = os.path.dirname(os.path.abspath(__file__))
            self.script_dir = self.system_check.get_script_path()

            self.failed_python_modules = []
            self.failed_packages = []

            self.ubuntu= opts.u
            self.custom = opts.c
            self.python = opts.p
            self.all = opts.a

            if not (opts.a or opts.c or opts.u or opts.p):
                self.all = True

            if self.all:
                self.ubuntu = True
                self.custom = True
                self.python = True

            if opts.i:
                self.install_path = opts.i

            else:
                self.install_path = ''.join([self.script_dir, '/settings/'])

            if opts.p:
                self.python_only = True

            user_home = os.path.expanduser(sudo_user)
            log_level = ''
            if opts.l:
                log_level = opts.l
            else:
                log_level = 'info'

            log_name = '.'.join([self.script_name.split('.')[0], 'log'])
            log_name = ''.join([self.home_dir, '/', log_name])

            if log_level.upper()  in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                numeric_level = 20
                numeric_level = getattr(logging, log_level.upper(), None)
                if not isinstance(numeric_level, int):
                    raise ValueError('Invalid log level: %s' % log_level)

                self.log = LogClass(log_name, numeric_level)
            else:
                exit()

            self.main()
        else:
            exit()

    def main(self):

        self.log.log('debug', 'A valid Ubuntu Distro was detected and the user is root')
        self.log.log('debug', 'Install Path: {}'.format(self.install_path))

        preconfig_file = ''.join([self.install_path, 'ubuntu-preconfigure.sh'])
        package_file = ''.join([self.install_path, 'packages_ubuntu.txt'])
        python_file = ''.join([self.install_path, 'modules_python.txt'])
        custom_file = ''.join([self.install_path, 'install_custom.sh'])
        postconfig_file = ''.join([self.install_path, 'ubuntu-postconfigure.sh'])

        os.chdir(self.script_dir)

        self.log.log('info', 'Beginning Install')

        if self.ubuntu:
            self.pre_configure(preconfig_file, 'Running pre-install commands')
            self.install_packages(package_file)
            self.post_configure(postconfig_file, 'Running post install Scripts')

        if self.python:
            self.install_pip_modules(python_file)

        if self.custom:
            self.execute_scripts(custom_file, 'Running Custom Scripts')

        failed_packages = self.get_failed_packages()

        if failed_packages.count > 0:
            for failed in failed_packages:
                self.log.log('info', 'Failed: Ubuntu Package Name: {}'.format(failed))
        else:
            self.log.log('info', 'SUCCEEDED: All selected packages were installed')

        failed_modules = self.get_failed_modules()
        if failed_modules.count > 0:
            for failed in failed_modules:
                self.log.log('info','Failed: Python Module: {}'.format(failed))
        else:
            self.log.log('info', 'SUCCEEDED: All selected Python modules were installed')

        self.log.log('info', 'Install Complete')

    def get_lines(self, file_name):
        array = []
        if os.path.exists(file_name):
            with open(file_name, 'r') as f:
                for line in f:
                    line=line.rstrip('\r\n')
                    if line[:1] != '#' and len(line) > 0:
                        array.append(line)
        else:
            self.log.log('critical', '{}'.format('File not found: {}'.format(file_name)))
        return array

    def get_failed_modules(self):
        return self.failed_python_modules

    def get_failed_packages(self):
        return self.failed_packages

    def install_packages(self, filename):
        returncode = ''

        self.log.log( 'info', 'Installing Packages')
        ubuntu_packages = self.get_lines(filename)

        for line in ubuntu_packages:

            package, comment = line.split('|')
            package = package.strip()
            comment = comment.strip()

            self.log.log('debug', 'Install test of Package: {}'.format(package))
            line = ' '.join(['apt-get -s install -y -o DPkg::Options::=--force-confold -o Acquire::ForceIPv4=true', package])

            line = ' '.join(['sudo', line])
            cmd = shlex.split(line)

            returncode = self.run_cmd(cmd)
            self.log.log('debug', 'Installed package test for {} returned code: {}'.format(package, returncode))

            if returncode == 0:
                line = ' '.join(['apt-get install -y -o DPkg::Options::=--force-confold -o Acquire::ForceIPv4=true', package])
                line = ' '.join(['sudo', line])
                cmd = shlex.split(line)

                self.log.log('info', 'Installing package: {}'.format(package))
                self.log.log('debug', 'Install command: {}'.format(line))

                returncode = self.run_cmd(cmd)

                self.log.log('debug', 'Install command: {}, Return Code: {}'.format(line, returncode))

                if returncode == 0:
                    self.log.log('info', 'SUCCESS: Installed package: {}'.format(package))

                else:
                    self.log.log('warn', 'FAILED: Installed of package: {}'.format(package))
                    self.package_install_error(package, returncode)
                    self.failed_packages.append(package)

            else:
                self.log.log('warn','FAILED: The package {} failed the install test. Error Code: {}'.format(package, returncode))
                self.failed_packages.append(package)

    def install_pip_modules(self, filename):
        returncode = ''

        cmds = ['apt-get install -y -o DPkg::Options::=--force-confold -o Acquire::ForceIPv4=true python-pip python3-pip',
                'pip2 install --upgrade pip', 'pip2 install --upgrade virtualenv', 'pip3 install --upgrade pip',
                'pip3 install --upgrade virtualenv']

        for line in cmds:
            line = ' '.join(['sudo', line])
            self.log.log('info', 'Running {}'.format(line))
            cmd = shlex.split(line)
            returncode = self.run_cmd(cmd)
            self.return_code_check(line, returncode)

            if returncode != 0:
                self.log.log('critical', 'FAILED: {} Return Code" {}, aborting'.format(line, returncode))
                return

        modules = self.get_lines(filename)

        for line in modules:
            module, purpose, p2, p3 = line.split('|')
            module = module.strip()
            purpose = purpose.strip()
            p2=p2.strip()
            p3=p3.strip()

            self.log.log('info', 'Installing: {}'.format(module))

            if '|' not in module and (p2 and p3):

                if p2.upper() == 'YES':
                    cmd2 = ' '.join(['sudo', 'pip2 install', module])
                    cmd2 = shlex.split(cmd2)

                    self.log.log('debug', 'Install into Python2 {}'.format(module))
                    returncode = self.run_cmd(cmd2)

                    if returncode != 0:
                        self.failed_python_modules.append('Python 2 Module: {}'.format(module))
                        self.log.log('debug', 'FAILED: to install module: {}'.format(module))

                if p3.upper() == 'YES':
                    cmd3 = ' '.join(['sudo', 'pip3 install', module])
                    cmd3 = shlex.split(cmd3)
                    self.log.log('debug', 'Installing into Python3 {}'.format(module))

                    returncode = self.run_cmd(cmd3)

                    if returncode != 0:
                        self.failed_python_modules.append('Python 3 Module: {}'.format(module))
                        self.log.log('debug', 'FAILED: to install module: {}'.format(module))

            else:
                self.log.log('debug', 'FAILED: to parse line {}'.format(line))

    def check_returncode(self, returncode, message):
        if returncode == 0:
            self.log.log('debug', 'Running {}: SUCCESS'.format(message))

        else:
            self.log.log('warn', 'Running {}: FAILED Return Code: {}'.format(message, returncode))

    def execute_scripts(self, file_name, message):
        self.log.log('info', '{}'.format(message))
        returncode = ''
        cmd = ''

        self.log.log('debug', 'Reading list of custom scripts from {}'.format(file_name))

        scripts = self.get_lines(file_name)

        for script in scripts:
            file_name = ''.join([self.install_path, script])
            returncode = self.execute_lines(file_name)

            if returncode != 0:
                self.log.log('warn', 'FAILED: {} Return Code: {}'.format(script, returncode))
            else:
                self.log.log('info', 'SUCCESS: {} Return Code: {}'.format(script, returncode))

    def execute_lines(self, filename):
        returncode = ''

        lines = self.get_lines(filename)

        for line in lines:
            if 'rm -rf / ' in line:
                self.log.log('critical', 'ABORTED: The deletion of the root directory was detected. Command line: {}'.format(line))
                sys.exit(1)

            line = ' '.join(['sudo', line])
            self.log.log('info', 'Running: {}'.format(line))

            cmd = shlex.split(line)

            returncode = self.run_cmd(cmd)

            if returncode != 0:
                self.log.log('warn', 'FAILED: {} Return Code: {}'.format(line, returncode))
            else:
                self.log.log('info', 'SUCCESS: {}'.format(line))
        return returncode

    def fix_package(self, try_cmd):
        # To be implemented in v2
        cmd = 'sudo dpkg --configure -a'
        cmd = shlex.split(cmd)
        cmd2 = shlex.shlex(try_cmd)
        returncode = self.run_cmd([cmd])
        returncode = self.run_cmd([cmd2])

        return returncode

    def package_install_error(self, package, returncode):

        if returncode == 100:
            self.log.log('debug', '{} was NOT Installed, Error Code: {} - Package not in repo'.format(package, returncode))

        elif returncode == 127:
            self.log.log('info', '{} was NOT installed, Error Code: {} - Errors were encountered during processing'.format(package, returncode))

        else:
            self.log.log('info', '{} was NOT installed, Error Code: {} - Unknown error'.format(package, returncode))

    def pre_configure(self, file_name, message):
        returncode = ''
        cmds = ['add-apt-repository universe', 'apt-get update','apt-get -y upgrade',
                'apt-get install -y -o DPkg::Options::=--force-confold -o Acquire::ForceIPv4=true debconf-utils',
                'apt-get check']

        for line in cmds:
            cmd = ' '.join(['sudo', line])
            self.log.log('info', 'Running {}'.format(cmd))
            cmd = shlex.split(cmd)
            returncode = self.run_cmd(cmd)
            self.return_code_check(line, returncode)

        returncode = self.execute_lines(file_name)
        self.log.log('info', 'Ubuntu Pre-configuration complete')

    def post_configure(self, file_name, message):
        returncode = ''
        self.log.log('info', message)

        line = 'sudo apt-get check'
        self.log.log('debug', 'Running {}'.format(line))
        cmd = shlex.split(line)

        returncode = self.run_cmd(cmd)

        if returncode == 0:
            self.log.log('debug', 'SUCCESS: Running {}'.format(line))

            cmds=['apt-get update', 'apt-get -y upgrade']

            for line in cmds:
                cmd = ' '.join(['sudo', line])
                self.log.log('debug', 'Running {}'.format(line))
                cmd = shlex.shlex(cmd)
                returncode = self.run_cmd(cmd)
                self.return_code_check(line, returncode)
        else:
            if returncode != 0:
                self.log.log('warning', 'FAILED:  Broken packages detected, attempting to correct')
                line = 'sudo dpkg --configure -a'
                self.log.log('info', 'Running {}'.format(line))

                cmd = shlex.split(line)

                returncode = self.run_cmd(cmd)
                self.return_code_check(line, returncode)

                if returncode == 0:
                    self.log.log('info', 'SUCCESS: Repair attempt was successful')
                else:
                    self.log.log('critical', 'FAILED: Repair attempt was unsuccessful')
                    return

        returncode = self.execute_lines(file_name)

        line = 'sudo apt-get -y autoremove'
        self.log.log('info', 'Running {}'.format(line))
        cmd = shlex.split(line)
        returncode = self.run_cmd(cmd)
        self.return_code_check(cmd, returncode)

        self.log.log('info', 'Ubuntu Post configuration complete')

    def return_code_check(self, cmd, return_code):
        if return_code == 0:
            self.log.log('debug', 'SUCCESS: Running {}'.format(cmd))

        else:
            self.log.log('debug', 'FAILED: Running {}'.format(cmd))

    def run_cmd(self, cmd, in_shell=False):
        std_out = ''
        std_err = ''
        returncode = ''

        try:
            response = subprocess.Popen(cmd, bufsize = -1, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=in_shell)
            returncode = response.wait()
            std_out, std_err = response.communicate()

            # if returncode !=0, something could be done here.	raise and error and handle it some how.

        except subprocess.CalledProcessError as e:
            self.log.log('debug', 'Subprocess Error: {}'.format(e.output))
            return returncode

        except ValueError:
            self.log.log('critical', 'Value Error: Invalid Arguments provided')
            self.log.log('critical', '{}'.format(std_err))
            return 1

        except OSError:
            self.log.log('critical', 'OS Error: The file did not exists')
            self.log.log('critical', '{}'.format(std_err))
            return 1

        except KeyboardInterrupt:
            sys.exit(1)

        except:
            self.log.log('critical', 'Unknown error returned by subprocess')
            self.log.log('critical', 'std_err was:\n{}'.format(std_err))
            return 1

        finally:
            self.log.log('debug', 'Command: {}, Return Code: {}'.format(cmd, returncode))
            return returncode


class LogClass():
    def __init__(self, logname, debug_level=20):

        if debug_level == 10:
            log_format = '%(asctime)s %(levelname)s: %(message)s'
        else:
            log_format ='%(levelname)s: %(message)s'

        logging.basicConfig(filename=logname, format=log_format, level=debug_level, filemode='w')

        console = logging.StreamHandler()
        console.setLevel(debug_level)

        formatter = logging.Formatter(log_format)

        console.setFormatter(formatter)

        logging.getLogger('').addHandler(console)

    def log(self, level='info', message=''):
        if level.lower() == 'debug':
            logging.debug(message)
        if level.lower() == 'info':
            logging.info(message)
        if level.lower() == 'warning':
            logging.warning(message)
        if level.lower() == 'error':
            logging.error(message)
        if level.lower() == 'critical':
            logging.critical(message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Load common software and python configurations',
                                     usage = '%(prog)s [options]',
                                     epilog = 'If no switches are given all options will be enabled, same as -a')
    parser.add_argument('-a', action = 'store_true', help='Install everything, same as -cpu')
    parser.add_argument('-c', action = 'store_true', help='Install Custom applications')
    parser.add_argument('-i', action = 'store', help = 'Path to the script files if not in the default location')
    parser.add_argument('-p', action = 'store_true', help='Install Python modules only')
    parser.add_argument('-u', action = 'store_true', help='Install Ubuntu packages only')
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s {version}, Written By {author}'.format(version = __version__, author = __author__ ))
    parser.add_argument('-l', '--log', action='store', dest="l", help='Change log level.  Default = "INFO"')

    opts = parser.parse_args()

    install_sift = InstallAppClass(opts)
