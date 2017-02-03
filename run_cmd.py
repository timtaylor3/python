#!/usr/bin/env python
"""
A function is an example of how to make system calls using the subprocess module
Python 2.7 and Python 3.5
"""

import subprocess

def run_cmd(cmd, in_shell=False, in_data=None):
	"""
	shell=True is bad in cases where the executed cmd comes from untrusted sources, ie external input
	In cases where shell=True are required, inputs need to be validated
	"""
	returncode = ''
	std_out = ''
	std_err = ''

	try:
		response = subprocess.Popen(cmd, stdin=in_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=in_shell)
		returncode = response.wait()
		std_out, std_err = response.communicate()

	except subprocess.CalledProcessError as e:
		print('Subprocess Error: {}'.format(e.output))
		return returncode, std_out, std_err

	finally:
		return returncode, std_out, std_err

if __name__ == "__main__":
	returncode = ''

	returncode, std_out, std_err = run_cmd('dir -l')
	print('Return Code: {}'.format(returncode))
	print('std_out: \n{}'.format(std_out))
	print('std_err: \n{}'.format(std_err))
