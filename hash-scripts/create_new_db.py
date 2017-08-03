#!/usr/bin/env python3
"""
This script creates the base DB tables and ingests the base data (VxShare and NSRL Hashes).
Requires Python 3
Tested on Windows 7 using Python 3.5.1 and 3.6.1
RDS 2.56 was loaded with no unicode errors
Only a good faith effort is made to ingest the lines from the NSRL file. The number of bad lines will be indicated if they occur.
"""

import argparse
import csv
import datetime
import logging
import os
import platform
import sqlite3
import sys

__author__ = "Tim Taylor"
__email__ = "jttaylor@us.ibm.com"
__credits__ = ""
__version__ = "1.1"
__status__ = "Production"


class LogClass():
	def __init__(self, debug_level=20):

		FORMAT = '%(levelname)s: %(message)s'
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
		LOG.log('Connection to db successful', 'info')
		return conn


def ingest_nsrl_data(nsrl_path, conn):
	'''
	Import nsrl data by recursion through the provided directory and import the data using the provided connection.
	Only one occurrence of an MD5 will be inserted to minimize the db size
	'''

	NSRL_table = 'CREATE TABLE IF NOT EXISTS nsrl (file_name TEXT NOT NULL, file_size TEXT NOT NULL, ' \
	             'md5_hash TEXT PRIMARY KEY, sha1_hash TEXT NOT NULL, crc32 TEXT, productcode TEXT, opsystemcode TEXT, ' \
	             'specialcode TEXT);'

	insert_nsrl_hashes = 'INSERT OR IGNORE INTO nsrl (file_name, file_size, md5_hash, sha1_hash, crc32, productcode, ' \
	                     'opsystemcode, specialcode) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
	nsrl_index = 'CREATE INDEX nsrl_index ON nsrl (md5_hash);'
	reset_records = 'DELETE FROM nsrl'
	drop_index = 'DROP INDEX IF EXISTS nsrl_index;'
	remove_duplicate_rows = 'delete from nsrl where rowid not in (select min(rowid)from nsrl group by md5_hash)'

	final_count = 0
	bad_count = 0

	c = conn.cursor()

	# Set up NSRL Table
	try:
		LOG.log('Setting up the NSRL table', 'info')
		c.execute(NSRL_table)

		LOG.log('Deleting all previous NSRL rows.', 'info')
		c.execute(reset_records)

		LOG.log('Dropping the NSRL index', 'info')
		c.execute(drop_index)

	except sqlite3.Error as e:
		LOG.log('SQLITE3 Error: {}'.format(e), 'critical')
		sys.exit()

	except:
		LOG.log('Unknown error creating NSRL Table', 'critical')
		sys.exit()

	# Import data
	finally:
		LOG.log('Importing NSRL hash data', 'debug')
		for root, dirs, files in os.walk(nsrl_path):
			for dirname in dirs:
				nsrl_dir = os.path.join(nsrl_path, dirname)
				nsrl_filename = os.path.join(nsrl_dir, 'NSRLFile.txt')
				LOG.log('Ingesting NSRL hash data from {}'.format(nsrl_filename), 'info')
				with open(nsrl_filename, mode='r', encoding='latin-1') as f:
					csv_reader = csv.DictReader(f, dialect='excel')
					try:
						for row in csv_reader:
							c.execute(insert_nsrl_hashes, [row['FileName'], row['FileSize'], row['MD5'], row['SHA-1'],
															row['CRC32'], row['ProductCode'], row['OpSystemCode'],
															row['SpecialCode']])
						conn.commit()

					except sqlite3.Error as e:
						LOG.log('SQLITE3 Error: {}'.format(e), 'critical')

					except UnicodeEncodeError as e:
						bad_count+=1
						pass

					except csv.Error as e:
						LOG.log('CSV Error: {}'.format(e), 'critical')

					finally:
						if bad_count > 0:
							LOG.log('Skipped {} hashes due to Unicode issues'.format(bad_count), 'info')
		try:
			LOG.log('Creating NSRL hash table index', 'info')
			c.execute(nsrl_index)


		except sqlite3.Error as e:
			LOG.log('SQLITE3 Error: {}'.format(e), 'critical')

		except:
			LOG.log('Unknown error importing NSRL Table', 'critical')
			sys.exit()

		try:
			LOG.log('Counting entries', 'debug')
			c.execute('SELECT COUNT() FROM nsrl;')
			final_count = c.fetchone()[0]

		except sqlite3.Error as e:
			LOG.log('SQLITE3 Error: {}'.format(e), 'critical')

		except:
			LOG.log('Unknown error cleaning up the NSRL Table', 'critical')
			sys.exit()

	return final_count


def ingest_vxshare_data(vxshare_path, conn):

	vxshare_table = 'CREATE TABLE IF NOT EXISTS vxshare_data (file_name text NOT NULL, file_size text NOT NULL, md5_hash text NOT NULL, sha1_hash text NOT NULL, ssdeep_hash text, first_hex text, last_hex text, crc32 text);'
	insert_vxshare_hashes = 'INSERT INTO vxshare_data (first_hex, last_hex, crc32, md5_hash, sha1_hash, ssdeep_hash, file_size, file_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
	md5_index = 'CREATE INDEX vxshare_md5_index ON vxshare_data (md5_hash);'
	sha1_index = 'CREATE INDEX vxshare_sha1_index ON vxshare_data (sha1_hash);'
	c = conn.cursor()

	count = 0

	c = conn.cursor()

	try:
		c.execute(vxshare_table)
		LOG.log('Created the VxShare Hash table', 'info')

	except sqlite3.Error as e:
		LOG.log('SQLITE3 Error: {}'.format(e), 'critical')
		sys.exit()

	except:
		LOG.log('Unknown error creating VxShare Table', 'critical')
		sys.exit()

	finally:
		LOG.log('Ingesting VxShare Hashes from'.format(vxshare_path), 'info')
		for filename in os.listdir(vxshare_path):
			fname = os.path.join(vxshare_path, filename)
			if os.path.isfile(fname) and filename[:1].isalnum():
				with open(fname,  mode='r', encoding='latin-1') as f:
					csv_reader = csv.reader(f, delimiter = ' ', dialect='excel')

					try:
						for row in csv_reader:
							if row[0][:1].isalnum():
								c.execute(insert_vxshare_hashes, [row[0], row[1], row[2], row[4], row[7], row[19].upper(), row[18].upper(), row[20]])
								count+=1

					except sqlite3.Error as e:
						LOG.log('SQLITE3 Error: {}'.format(e), 'critical')

					except csv.Error as e:
						LOG.log('CSV Error {} reading {}'.format(e, fname), 'critical')
						pass

		conn.commit()
		LOG.log('Creating VxShare table indexes', 'info')
		c.execute(md5_index)
		c.execute(sha1_index)

	return count


def main(args):
	start_time = datetime.datetime.now()

	# Setup logging
	global LOG
	log_level = 'debug'

	numeric_level = getattr(logging, log_level.upper(), None)
	if not isinstance(numeric_level, int):
		raise ValueError('Invalid log level: %s' % log_level)

	# LOG = LogClass('uac.log', numeric_level)
	LOG = LogClass(numeric_level)

	conn = create_connection(args.d)

	if args.m:
		if os.path.isdir(args.m):
			malware_hash_count = ingest_vxshare_data(args.m, conn)
			LOG.log('Ingested {:,} vxshare_data hashes'.format(int(malware_hash_count)), 'info')
		else:
			LOG.log('{} is a file, specify a directory'.format(args.m), 'info')

	if args.n:
		if os.path.isdir(args.n):
			nsrl_hash_count = ingest_nsrl_data(args.n, conn)
			LOG.log('Imported {:,} NSRL hashes'.format(int(nsrl_hash_count)), 'info')
		else:
			LOG.log('{} is a file, specify a directory'.format(args.m), 'info')

	end_time = datetime.datetime.now()
	p_time = end_time - start_time
	run_minutes = int(p_time.total_seconds() / 60)
	LOG.log('Runtime {} minutes'.format(str(run_minutes)), 'info')


if __name__ == "__main__":
	parser = argparse.ArgumentParser('Output a matching lines based on hash values.')
	parser.add_argument('-d', required=True, help='Path and file name to the database (hash-db.db)')
	parser.add_argument('-m', required=False, help='Path to the VxShare text files to import (Optional)')
	parser.add_argument('-n', required=False, help='Path to NSRL data (will recurse and find files to import). (Optional')

	args = parser.parse_args()

	if int(platform.python_version()[0]) < 3:
		raise Exception('This script requires python 3')
	else:
		main(args)