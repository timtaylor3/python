#!/usr/bin/env python
"""
A function is an example of how to make system calls using the subprocess module
Python 2.7 and Python 3.5
Windows 7 throughs an OSError exception.
"""
import shlex
import subprocess
import sys

def run_cmd(cmd, in_shell=False, in_data=None):
    std_out = ''
    std_err = ''
    returncode = ''

    try:
        response = subprocess.Popen(cmd, bufsize=-1, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=in_shell)
        returncode = response.wait()
        std_out, std_err = response.communicate()

    except subprocess.CalledProcessError as e:
        return returncode

    except ValueError:
        print('Value Error: Invalid Arguments provided')
        print('{}'.format(std_err))
        return 1

    except OSError:
        print('OS Error: The file did not exists')
        print('{}'.format(std_err))
        return 1

    except KeyboardInterrupt:
        sys.exit(1)

    except:
        print('Unknown error returned by subprocess')
        print('std_err was:\n{}'.format(std_err))
        return 1

    finally:
        return returncode, std_out, std_err


if __name__ == "__main__":

    line = 'dir -l'
    cmd = shlex.split(line)

    returncode, std_out, std_err = run_cmd(cmd)
    print('Return Code: {}'.format(returncode))
    print('std_out: \n{}'.format(std_out))
    print('std_err: \n{}'.format(std_err))
