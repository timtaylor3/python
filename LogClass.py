#!/usr/bin/env python
"""
A very basic logging class, nothing fancy
Use at your own risk
Tested on Windows 7, Ubuntu 16.04 x86_64
Python 2.7 and Python 3.5
"""
__author__ = "Tim Taylor"
__email__ = "timtaylor3@yahoo.com"
__version__ = "0.1"
__status__ = "Development"
__credit__ = ["Logging Cookbook", "The open source community"]

import argparse
import logging
import os

class LogClass():
	def __init__(self, logname, debug_level=20):

		FORMAT = '%(levelname)s: %(message)s'
		logging.basicConfig(filename=logname, format=FORMAT, level=debug_level, filemode='w')

		console = logging.StreamHandler()
		console.setLevel(debug_level)

		formatter = logging.Formatter(FORMAT)

		console.setFormatter(formatter)

		logging.getLogger('').addHandler(console)

	def log(self, level='info', message=''):
		if level == 'debug':
			logging.debug(message)
		if level == 'info':
			logging.info(message)
		if level == 'warning':
			logging.warning(message)
		if level == 'error':
			logging.error(message)
		if level == 'critical':
			logging.critical(message)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='LogClass tester', usage='%(prog)s [options]')
	parser.add_argument('-l', '--log', action='store', dest="l", help='Change log level.  Default = "DEBUG"')

	opts = parser.parse_args()
	if opts.l:
		log_level = opts.l
	else:
		log_level = 'debug'

	numeric_level = getattr(logging, log_level.upper(), None)
	if not isinstance(numeric_level, int):
		raise ValueError('Invalid log level: %s' % log_level)


	log = LogClass('test.log', numeric_level)

	log.log('debug', str(numeric_level))
	log.log('info', str(numeric_level))
	log.log('warning', str(numeric_level))
	log.log('error', str(numeric_level))
	log.log('critical', str(numeric_level))