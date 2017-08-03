#!/usr/bin/env python3
"""

To install the required modules:  pip3 install -r requirements.txt

REQUIRES: Python3
Tested on Windows 7 using Python 3.6.1
Should run on any OS using Python 3.  
XlsxWriter (easy_install XlsxWriter or pip3 install XlsxWriter

KNOWN ISSUES:
Python 3.6.1 introduced an SSL Cert verify issue when running on OSX which is a Python.org/Apple issue.
Run this command to fix if the issue is encountered where #.# is the version of python:  

/Application/Python #.#/Install Certificates.command

TODO Items:
TODO: Output results for multiple major A/V vendors such as Symantec, McAfee, MS, TrendMicro, Malwarebytes
TODO: Allow user to specify one additional A/V of interest

RELEASE Notes:
Rel 1.1: CSV Code clean up
		 Added more VxShare Data
		 Bolded MZ and ELF VxShare matches on the Excel out put
Rel 1.0.1: Bug Fix and Code Cleanup
Rel 1.0: Initial Release


"""
import argparse
import csv
import datetime
import json
import logging
import os
import platform
import sqlite3
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import xlsxwriter


__author__  = "Tim Taylor"
__email__   = "timtaylor3@yahoo.com"
__version__ = "1.1"
__status__  = "Production"

class LogClass():
	def __init__(self, debug_level=20):

		#FORMAT = '%(levelname)s: %(message)s'
		FORMAT = '%(message)s'
		logging.basicConfig(format=FORMAT, level=debug_level)


	def log(self, message, level='info'):
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


def fix_csv_output(outfile, prefix):
	new_file_name = ''
	if os.sep not in outfile:
		new_file_name = ''.join([prefix, outfile])
	else:
		dir, file_name =  os.path.split(outfile)
		file_name = ''.join([prefix, file_name])
		new_file_name = os.path.join(dir, file_name)

	return new_file_name


def get_vt_api_key():
	api_key = ''
	with open('api-key.txt', 'r', encoding='latin-1') as f:
		for line in f:
			api_key = line.rstrip()
			return api_key.strip()

	if len(api_key) != 64:
		LOG.log('Check your api_key.', 'info')


def create_connection(db_file):
	""" create a database connection to a SQLite database """
	try:
		conn = sqlite3.connect(db_file)

	except sqlite3.Error as e:
		LOG.log(e, 'critical')
		sys.exit()

	except:
		LOG.log('Unknown error creating connection', 'critical')
		sys.exit()

	finally:
		LOG.log('Connection to db successful', 'debug')
		return conn


def delete_zero_length(table, conn):
	# sql = 'DELETE FROM {} where md5_hash = "d41d8cd98f00b204e9800998ecf8427e";')
	sql = 'DELETE FROM {} WHERE file_size = "0";'.format(table)
	count = 0

	try:
		c = conn.cursor()
		c.execute(sql)
		count = c.rowcount
		conn.commit()

	except sqlite3.Error as e:
		LOG.log(e, 'critical')
		sys.exit()

	except:
		LOG.log('Unknown error removing zero length records from the table: {}'.format(table), 'warning')
		sys.exit()

	finally:
		return count


def update_db_vt_matches(conn):


	vt_table = 'CREATE TABLE vt_results (md5_hash TEXT, sha1_hash TEXT, detection_ratio TEXT, scan_date TEXT, scan_url TEXT, symantec_detection TEXT, s_version TEXT, s_update TEXT);'
	insert_vt_matches = 'INSERT INTO vt_results (md5_hash, sha1_hash, detection_ratio, scan_date, scan_url, symantec_detection, s_version, s_update) VALUES (?, ?, ?, ?, ?, ?, ?, ?);'
	create_vt_index = 'CREATE INDEX vt_results_index ON vt_results (md5_hash);'
	c = conn.cursor()

	try:
		c.execute('DROP TABLE IF EXISTS vt_results')
		c.execute(vt_table)
		LOG.log('Virus Total Results table created', 'info')

	except sqlite3.Error as e:
		LOG.log('SQLITE3 Error: {}'.format(e), 'critical')
		sys.exit()

	except:
		LOG.log('Unknown error creating the Virus Total table', 'info')
		sys.exit()

	finally:
		api_key = get_vt_api_key()

		sleep_time = 16
		if args.p:
			sleep_time = 0

		try:
			LOG.log('Finding Virus Total matches based on VxShare Library Matches', 'info')
			sql = 'SELECT hashes.file_name, hashes.file_ext, hashes.file_size, hashes.md5_hash, hashes.sha1_hash FROM hashes INNER JOIN vxshare_data ON hashes.md5_hash=vxshare_data.md5_hash;'
			results = c.execute(sql)
			for row in results:
				detection_ratio, scan_date, scan_url, symantec_detection, s_version, s_update = query_VT(row[3], api_key)
				time.sleep(sleep_time)
				c.execute(insert_vt_matches, (row[3], row[4], detection_ratio, scan_date, scan_url, symantec_detection, s_version, s_update))

			conn.commit()

			LOG.log('Creating vt_results table index', 'info')
			c.execute('DROP INDEX IF EXISTS vt_results_index')
			c.execute(create_vt_index)


		except sqlite3.Error as e:
			LOG.log('SQLITE3 Error: {}'.format(e), 'critical')

		except TypeError as e:
			LOG.log('TypeError: {}'.format(e), 'critical')

		except:
			LOG.log('Unknown error updating the vt table', 'critical')

		return c.execute('SELECT Count(*) FROM vt_results;').fetchone()[0]


def query_VT(hash, api_key):
	'''HTTP Response code 204 is returned when exceeding request limit'''
	detection_ratio = ''
	scan_date = ''
	scan_url = ''
	symantec_detection = ''
	version = ''
	update = ''

	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": hash, "apikey": api_key}
	response = ' '

	try:
		data = urllib.parse.urlencode(parameters)
		data = data.encode('ascii')
		req = urllib.request.Request(url, data)
		response = urllib.request.urlopen(req)

	except urllib.error.HTTPError as e:
		if e.code == 403:
			LOG.log('Check the api key. Error: {} {}'.format(e.code, e.reason), 'warning')

		elif e.code == 204:
			LOG.log('Query rate exceeded request limit', 'warning')

		else:
			LOG.log('The error {} occurred'.format(e.code), 'warning')

			if 'CERTIFICATE_VERIFY_FAILED' in e:
				LOG.log('If you are using a mac, run "/Application/Python #.#/Install Certificates.command", '
					  'where #.# is the version of python being used, then retry the script', 'critical')

	try:
		vt_data = response.read()
		dict = json.loads(vt_data.decode('utf-8'))

		response_code = dict['response_code']

		if response_code == 1:
			detection_ratio = str(dict['positives']) + '/' + str(dict['total'])

			scan_date = dict['scan_date']
			scan_url = dict['permalink']

			if 'Symantec' in dict['scans']:
				dict = dict['scans']['Symantec']
				symantec_detection = dict['detected']
				if symantec_detection:
					symantec_detection = 'Symantec Name: {}'.format(dict['result'])
					version = dict['version']
					update = dict['update']
				else:
					symantec_detection = 'Symantec did not detect as malware'
			else:
				symantec_detection = 'There were no Symantec results returned by VirusTotal'


	except AttributeError as e:
		LOG.log('Atribute Error: {} An error parsing json into the lookup dictionary'.format(e), 'warning')

	except TypeError as e:
		LOG.log('Type Error: {}'.format(e), 'warning')

	except ValueError as e:
		LOG.log ('ValueError: {}'.format(e), 'warning')

	except KeyError as e:
		LOG.log('KeyError: {}'.format(e), 'warning')

	except:
		LOG.log('Sample MD5 {} could not be looked up due to an error'.format(md5_sum), 'warning')

	return detection_ratio, scan_date, scan_url, symantec_detection, version, update


def import_single_hash(args, conn):

	api_key = get_vt_api_key()
	hash_value = args.hash
	md5 = False
	sha1 = False
	sha256 = False

	if len(hash_value) == 32:
		md5 = True

	elif len(hash_value) == 40:
		sha1 = True

	elif len(hash_value) == 64:
		sha256 = True

	nsrl_sql = ''
	vxshare_sql = ''

	if md5:
		nsrl_sql = ''.join(['SELECT distinct nsrl.file_name, nsrl.file_size, nsrl.md5_hash, nsrl.sha1_hash, crc32 '
		                    'FROM nsrl '
		                    'WHERE nsrl.md5_hash = "', hash_value, '"'])

		vxshare_sql = ''.join(['SELECT distinct vxshare_data.file_name, vxshare_data.file_size, vxshare_data.md5_hash, vxshare_data.sha1_hash, vxshare_data.ssdeep_hash, vxshare_data.crc32, vxshare_data.first_hex, vxshare_data.last_hex '
		                       'FROM vxshare_data '
		                       'WHERE vxshare_data.md5_hash = "', hash_value, '"'])

	elif sha1:
		nsrl_sql = ''.join(['SELECT distinct nsrl.file_name, nsrl.file_size, nsrl.md5_hash, nsrl.sha1_hash, crc32 '
		                    'FROM nsrl '
		                    'WHERE nsrl.sha1_hash = "', hash_value, '"'])

		vxshare_sql = ''.join(['SELECT distinct vxshare_data.file_name, vxshare_data.file_size, vxshare_data.md5_hash, vxshare_data.sha1_hash, vxshare_data.ssdeep_hash, vxshare_data.crc32, vxshare_data.first_hex, vxshare_data.last_hex '
		                       'FROM vxshare_data '
		                       'WHERE vxshare_data.sha1_hash = "', hash_value, '"'])

	elif sha256:
			LOG.log('NSRL and VxShare hashes are not available for lookup.  Checking Virus Total')

	LOG.log('Checking {} from the command line'.format(hash_value), 'info')
	c = conn.cursor()

	if md5 or sha1:
		# NSRL Lookups
		results = c.execute(nsrl_sql)
		LOG.log('NSRL Results')
		LOG.log('File Name, File Ext, Fize Size, MD5 Hash, SHA1 Hash, CRC32')
		for row in results:
			LOG.log('{}, {}, {}, {}, {} {}'.format(row[0], row[1], row[2], row[3], row[4], row[5]))

		results = c.execute(vxshare_sql)
		LOG.log('VxShare Results')
		LOG.log('VxShare File Name, Fize Size, MD5 Hash, SHA1 Hash, SSDEEP Hash, CRC32, First 32 Hex, Last 32 Hex')
		for row in results:
			LOG.log('{}, {}, {}, {} {} {} {} {}'.format(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]))

	#VT lookups
	detection_ratio, scan_date, scan_url, symantec_detection, s_version, s_update = query_VT(hash_value, api_key)
	LOG.log('VT Results')
	LOG.log('Detection Ratio, Symantec Detection, Permalink')
	LOG.log('{}, {}, {}'.format(detection_ratio, symantec_detection, scan_url))


def import_hashes(args, conn):

	count = 0
	compare_file = ''
	insert_rows = ''
	create_table = 'CREATE TABLE hashes (file_name TEXT, file_ext TEXT, file_size TEXT, ' \
	               'md5_hash TEXT NOT NULL, sha1_hash TEXT);'
	create_index = 'CREATE INDEX hashes_index ON hashes (md5_hash);'
	drop_table = 'DROP TABLE IF EXISTS hashes'
	drop_index = 'DROP INDEX IF EXISTS hashes_index'

	if args.u:
		LOG.log('Setting up to ingest hashes from {}'.format(args.u), 'info')
		compare_file = args.u

		insert_rows = 'INSERT INTO hashes (file_size, md5_hash, sha1_hash, file_name, file_ext) VALUES (?, ?, ?, ?, ?);'

	elif args.s:
		LOG.log('Setting up to ingest hashes from {}'.format(args.s), 'info')
		compare_file = args.s
		insert_rows = 'INSERT INTO hashes (md5_hash) VALUES (?);'

	elif args.m:
		LOG.log('Setting up to ingest hashes from {}'.format(args.m), 'info')
		compare_file = args.m
		insert_rows = 'INSERT INTO hashes (md5_hash, file_name, file_ext) VALUES (?, ?, ?);'

	else:
		LOG.log('No file to ingest')
		sys.exit(1)

	c = conn.cursor()
	try:
		c.execute(drop_table)
		c.execute(create_table)

	except sqlite3.Error as e:
		LOG.log('SQLITE3 Error: {}'.format(e), 'critical')
		sys.exit()

	except:
		LOG.log('Unknown error creating table', 'info')
		sys.exit()

	finally:
		LOG.log('Ingesting rows', 'info')
		row = ''

		with open(compare_file, mode='r', encoding='latin-1') as f:
			csv_reader = ''
			if args.s or args.u:
				csv_reader = csv.reader(f, delimiter=',', dialect='excel')
			elif args.m:
				csv_reader = csv.reader(f, delimiter=' ', dialect='excel')
			count = 0
			try:

				for row in csv_reader:
					# single column
					if args.s:
						if row[0][:1].isalnum():
							c.execute(insert_rows, [row[0]])
							count += 1

					# Hashdeep
					if args.u:
						if row[0][:1].isdigit():
							file_ext = os.path.splitext(row[3])[1][1:]
							c.execute(insert_rows, [row[0], row[1], row[2], row[3], file_ext])
							count += 1

					# md5sum
					if args.m:
						if row[0][:1].isdigit():
							file_ext = os.path.splitext(row[1])[1][1:]
							c.execute(insert_rows, [row[0], row[1], file_ext])
							count += 1

			except ValueError as e:
				LOG.log('ValueError: {}, line:  {} '.format(e, row), 'warning')

			except sqlite3.Error as e:
				LOG.log('SQLITE3 Error: {}'.format(e), 'critical')

			except csv.Error as e:
				LOG.log('CSV Error: {}'.format(e), 'critical')

			finally:
				conn.commit()
				LOG.log('Creating table index', 'info')
				c.execute(drop_index)
				c.execute(create_index)

	return count


def output_to_csv(outfile, source, conn):
	LOG.log('Retrieving {} Matches'.format(source))
	fixed = ''.join([source, '_'])
	outfile = fix_csv_output(outfile, fixed)
	sql =''

	header = (['File Name', 'File Ext', 'File Size', 'MD5 Hash', 'SHA1 Hash'])

	if source == 'VirusTotal':

		sql = 'select distinct hashes.file_name, hashes.file_ext, hashes.file_size, hashes.md5_hash, hashes.sha1_hash, ' \
		      'vt_results.detection_ratio, vt_results.scan_date, vt_results.symantec_detection, vt_results.s_update, vt_results.s_version, vt_results.scan_url ' \
		      'FROM hashes ' \
		      'INNER JOIN vt_results ON hashes.md5_hash=vt_results.md5_hash;'

		header = (['File Name', 'File Ext', 'File Size', 'MD5 Hash', 'SHA1 Hash', 'Detection Ratio', 'Scan Date', 'Symantec Detection', 'Scan Update', 'Scan Version', 'VT URL'])

	elif source == 'VxShare':
		sql = 'SELECT distinct hashes.file_name, hashes.file_ext, hashes.file_size, hashes.md5_hash, hashes.sha1_hash, vxshare_data.ssdeep_hash, vxshare_data.crc32, vxshare_data.first_hex, vxshare_data.last_hex, vxshare_data.file_name ' \
		      'FROM hashes ' \
		      'INNER JOIN vxshare_data ' \
		      'ON hashes.md5_hash=vxshare_data.md5_hash;'

		header = (['File Name', 'File Ext', 'File Size', 'MD5 Hash', 'SHA1 Hash', 'SSDEEP Hash', 'CRC32', 'First 32 HEX','Last 32 Hex', 'VxShare Hash File'])

	elif source == 'NSRL':
		sql = 'SELECT distinct hashes.file_name, hashes.file_ext, hashes.file_size, hashes.md5_hash, hashes.sha1_hash ' \
		      'FROM hashes ' \
		      'INNER JOIN nsrl ' \
		      'ON hashes.md5_hash=nsrl.md5_hash;'

	elif source == 'No':
		sql = 'SELECT distinct hashes.file_name, hashes.file_ext, hashes.file_size, hashes.md5_hash, hashes.sha1_hash ' \
		      'FROM hashes ' \
		      'WHERE hashes.md5_hash not in ' \
		      '(SELECT vxshare_data.md5_hash FROM vxshare_data) AND ' \
		      'hashes.md5_hash not in ' \
		      '(SELECT vt_results.md5_hash FROM vt_results);'

	count = 0

	try:

		c = conn.cursor()
		results = c.execute(sql)


		LOG.log('Writing {} matches to csv'.format(source), 'info')

		with open(outfile, mode='w', encoding='latin-1', newline='') as csv_file:
			try:
				writer = csv.writer(csv_file, quoting=csv.QUOTE_NONE, dialect='excel')

				writer.writerow(header)

				for row in results:

					if source == 'VirusTotal':
						writer.writerow([row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10]])

					elif source == 'VxShare':
						writer.writerow([row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]])

					elif source == 'NSRL':
						writer.writerow(row['file_name'], row['file_ext'], row['file_size'], row['md5_hash'], row['sha1_hash'])

					elif source == 'No':
						writer.writerow([row[0], row[1], row[2], row[3], row[4]])

					count+=1

			except csv.Error as e:
				LOG.log('CSV Error: {}'.format(e), 'warning')

	except sqlite3.Error as e:
		LOG.log('SQLITE3 Error: {}'.format(e), 'critical')

	except csv.Error as e:
		LOG.log('CSV Error: {}'.format(e), 'warning')

	return count


def create_excel_file(outfile):

	try:
		workbook = xlsxwriter.Workbook(outfile)
		workbook.set_properties({
			'title': 'Hash Results',
			'company': 'IBM CSIRT',
			'comments': 'Created by the hash-import script',
		})


	except:
		LOG.log('Unhandled Error', 'critical')
		sys.exit(1)

	finally:
		return workbook


def output_to_excel(workbook, source, conn):

	LOG.log('Retrieving {} Matches'.format(source))
	sql = ''
	header = ''
	filter = ''
	if source == 'VirusTotal':
		sql = 'SELECT DISTINCT hashes.file_name, hashes.file_ext, hashes.file_size, hashes.md5_hash, hashes.sha1_hash, ' \
		      'vt_results.detection_ratio, vt_results.scan_date, vt_results.symantec_detection, vt_results.s_update, ' \
		      'vt_results.s_version, vt_results.scan_url ' \
		      'FROM hashes ' \
		      'INNER JOIN vt_results ON hashes.md5_hash=vt_results.md5_hash;'
		header = (['File Name', 'File Ext', 'File Size', 'MD5 Hash', 'SHA1 Hash', 'Detection Ratio', 'Scan Date',
		           'Symantec Detection', 'Scan Update', 'Scan Version', 'VT URL'])
		filter = 'A1:K1'

	elif source == 'VxShare':
		sql = 'SELECT DISTINCT hashes.file_name, hashes.file_ext, vxshare_data.file_size, vxshare_data.md5_hash, vxshare_data.sha1_hash, vxshare_data.ssdeep_hash, vxshare_data.crc32, vxshare_data.first_hex, vxshare_data.last_hex, vxshare_data.file_name ' \
		      'FROM hashes ' \
		      'INNER JOIN vxshare_data ' \
		      'ON hashes.md5_hash=vxshare_data.md5_hash;'

		header = (['File Name', 'File Ext', 'File Size', 'MD5 Hash', 'SHA1 Hash', 'SSDEEP Hash', 'CRC32', 'First 32 HEX', 'Last 32 Hex', 'VxShare Hash File'])
		filter = 'A1:J1'

	elif source == 'NSRL':
		sql = 'SELECT distinct hashes.file_name, hashes.file_ext, hashes.file_size, hashes.md5_hash, hashes.sha1_hash ' \
		      'FROM hashes ' \
		      'INNER JOIN nsrl ' \
		      'ON hashes.md5_hash=nsrl.md5_hash;'
		header = (['File Name', 'File Ext', 'File Size', 'MD5 Hash', 'SHA1 Hash'])
		filter = 'A1:E1'

	elif source == 'No':
		sql = 'SELECT distinct hashes.file_name, hashes.file_ext, hashes.file_size, hashes.md5_hash, hashes.sha1_hash ' \
		      'FROM hashes ' \
		      'WHERE hashes.md5_hash not in ' \
		      '(SELECT vxshare_data.md5_hash FROM vxshare_data) AND ' \
		      'hashes.md5_hash not in ' \
		      '(SELECT vt_results.md5_hash FROM vt_results);'
		header = (['File Name', 'File Ext', 'File Size', 'MD5 Hash', 'SHA1 Hash'])
		filter = 'A1:E1'

	LOG.log('Writing {} Matches to Excel'.format(source))
	c = conn.cursor()
	results = c.execute(sql)

	sheet_name = ' '.join([source, 'Results'])
	worksheet = workbook.add_worksheet(sheet_name)
	bold = workbook.add_format({'bold': True})

	col = 0
	row = 0
	for item in header:
		worksheet.write(row, col, item, bold)
		col += 1

	worksheet.autofilter(filter)

	try:
		col = 0
		row = 1

		for item in results:
			while (len(item) != (col)):
				worksheet.write(row, col, item[col])
				col+=1
			row+=1
			col=0

	except IndexError as e:
		print(e)

	if source == 'VxShare':
		range = ''.join(['H1:H', str(row)])
		bold = workbook.add_format({'bold': True})
		# MZ
		worksheet.conditional_format(range, {'type': 'text', 'criteria': 'begins with', 'value': '4d5a', 'format': bold})
		# ELF
		worksheet.conditional_format(range, {'type': 'text', 'criteria': 'begins with', 'value': '7f454c46', 'format': bold})

	return row - 1


def main(args):
	start_time = datetime.datetime.now()

	# Setup logging
	global LOG
	log_level = 'info'
	numeric_level = getattr(logging, log_level.upper(), None)
	if not isinstance(numeric_level, int):
		raise ValueError('Invalid log level: %s' % log_level)
	LOG = LogClass(numeric_level)

	# Setup db Connections
	conn = create_connection(args.d)

	if args.m or args.u or args.s:
		raw_lines = import_hashes(args, conn)

		delete_count = delete_zero_length('hashes', conn)
		vt_matches = update_db_vt_matches(conn)

		nsrl_matches = ''
		vxshare_matches = ''
		non_matches = ''

		if args.x:
			# Excel output was selected
			excel_file = create_excel_file(args.x)
			vxshare_matches = output_to_excel(excel_file, 'VxShare', conn)
			vt_matches = output_to_excel(excel_file, 'VirusTotal', conn)
			nsrl_matches = output_to_excel(excel_file, 'NSRL', conn)
			non_matches = output_to_excel(excel_file, 'No', conn)
			excel_file.close()

		if args.c:
			# csv output was selected
			vxshare_matches = output_to_csv(args.c, 'VxShare', conn)
			vt_matches = output_to_csv(args.c, 'VirusTotal', conn)
			nsrl_matches = output_to_csv(args.c, 'NSRL', conn)
			non_matches = output_to_csv(args.c, 'No', conn)


		if args.x or args.c:
			# Output some stats
			LOG.log('Raw Hashes Ingested: {:,}'.format(int(raw_lines)), 'info')
			LOG.log('Deleted {:,} zero length files from the hash ingest'.format(delete_count), 'info')
			LOG.log('NSRL Matches: {:,}'.format(nsrl_matches), 'info')
			LOG.log('VxShare Matches: {:,}'.format(vxshare_matches), 'info')
			LOG.log('VirusTotal Matches: {:,}'.format(vt_matches), 'info')
			LOG.log('Non-Matches: {:,}'.format(non_matches), 'info')

		end_time = datetime.datetime.now()
		p_time = end_time - start_time
		run_minutes = int(p_time.total_seconds() / 60)
		LOG.log('Runtime: {} minutes'.format(run_minutes), 'info')

	if args.hash:
		import_single_hash(args, conn)


if __name__ == "__main__":
	parser = argparse.ArgumentParser('Output a matching lines based on hash values.')
	group = parser.add_mutually_exclusive_group()
	parser.add_argument('-d', required=True, help="sqlite db", default='hash.db')
	parser.add_argument('-c', required=False, help='The output CSV file')
	group.add_argument('-s', required=False, help='Ingest a single column text file of hash values')
	group.add_argument('-u', required=False, help='Hashdeep formatted text file')
	group.add_argument('-m', required=False, help='MD5sum formatted text file')
	group.add_argument('-hash', required=False, help='A single MD5, SHA1 or SHA256 hash value on the command line, output to standard out')
	parser.add_argument('-x', required=False, help='The output an Excel Workbook')
	parser.add_argument('-p', action='store_true', required=False, help='The provide key is a private key and no query delay is needed')

	args = parser.parse_args()

	if int(platform.python_version()[0]) < 3:
		raise Exception('This script requires python 3')
	else:
		main(args)
