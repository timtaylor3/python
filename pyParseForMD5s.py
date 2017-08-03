#!/usr/bin/env python
"""
This file parses out the Mandiant IOCs and creates a text file to be used to create an EnCase Hash Set.
If a string looks like an md5 to regex, it will be added to the output.
This script has been tested on Python 2.7, 3.4 and 3.5
"""
from __future__ import with_statement
import argparse
import csv
import os
import re
from xml.etree import ElementTree

__author__  = "Tim Taylor"
__email__   = "jttaylor@us.ibm.com"
__credits__ = ""
__version__ = "1.0"
__status__  = "Use at your own risk"

def getMD5s(args):
    """
    :param file: A directory with text files containing MD5s.
    :return: A list of file names, 0 and md5s
    """
    MD5_PATTERN = re.compile(r'[a-f\d]{32}')
    md5s=[]
    tree = ''
    directory = args.s
    xml = args.i

    for filename in os.listdir(directory):
        fname = os.path.join(directory, filename)
        with open(fname, 'rt') as f:
            if xml:
                tree = ElementTree.parse(f)

                for node in tree.iter():
                    if node.attrib == ({'type': 'md5'}):
                        md5s.append([filename + '\t0\t' + node.text + '\t'])
            else:
                data = f.read()
                file_md5s = re.findall(MD5_PATTERN, data)

                for item in file_md5s:
                    md5s.append([filename + '\t0\t' + item + '\t'])
    return md5s

def writeCSV(data, path):
    '''
    Writes out the parsing results to a tab delimited text file.
    :param: A list and an output file
    :return:  Nothing
    '''
    with open(path, 'a') as csv_file:
        writer = csv.writer(csv_file)

        for line in data:
            writer.writerow(line,)

def main(args):
    md5s =[]
    md5s = getMD5s(args)

    writeCSV(md5s, args.o)

if __name__ == "__main__":
    parser = argparse.ArgumentParser('Create a Text file to be imported into an EnCase7 Hash Library.')
    parser.add_argument('-s', required=True, help='Source Directory, no recursion')
    parser.add_argument('-i', action='store_true', help="Treat files as Mandiant IOCs. ('type': 'md5')")
    parser.add_argument('-o', required=True, help='The output file (csv.)')
    args = parser.parse_args()

    if args.s is not None and args.o is not None:
        main(args)
    else:
        parser.print_help()
