# !/usr/bin/env python3


import argparse
import csv
import json
import os
import platform
import pyewf
import xlsxwriter
from fnmatch import fnmatch

__author__  = "Tim Taylor"
__email__   = "timtaylor3@yahoo.com"
__version__ = "0.1"
__status__  = "Development"


def get_ewf_files(top, file_exts):
    ewf_file_sets=[]
    for path, directories, files in os.walk(top):
        for file_name in files:
            for file_ext in file_exts:
                if fnmatch(file_name, file_ext):
                    ewf_file_sets.append(os.path.join(path, file_name))
    return ewf_file_sets


def json_output(data):
    print(json.dumps(data, sort_keys=False, indent=4))


def csv_output(toCSV, csv_name):
    with open(csv_name, 'w', encoding='utf8', newline='') as output_file:
        fc = csv.DictWriter(output_file, fieldnames=toCSV[0].keys(), )
        fc.writeheader()
        fc.writerows(toCSV)


def xlsx_output(toXLSX, xlsx_name):
    # Create a workbook and add a worksheet.
    workbook = xlsxwriter.Workbook(xlsx_name)
    worksheet = workbook.add_worksheet()
    worksheet.set_column('A:L')
    worksheet.add_table('A1:L1', {'data': toXLSX,
                                   'columns': [{'header': 'Image Set'},
                                               {'header': 'Case Number'},
                                               {'header': 'Description'},
                                               {'header': 'Examiner Name'},
                                               {'header': 'Evidence Number'},
                                               {'header': 'Notes'},
                                               {'header': 'Acq Date'},
                                               {'header': 'System Date'},
                                               {'header': 'Acq Operating System'},
                                               {'header': 'Acq Software Version'},
                                               {'header': 'MD5'},
                                               {'header': 'SHA1'},
                                               {'autofilter': 1}
                                               ]})

    row = 1

    for row_data in toXLSX:
        col = 0
        for cell_data in row_data.values():
            worksheet.write(row, col, cell_data)
            col += 1
        row += 1

    workbook.close()


def get_header_info():
    return ewf_handle.get_header_values()


def get_hash_values():
    return ewf_handle.get_hash_values()


def main(args):
    root = args.d
    patterns = ["*.E01", "*.Ex01", "*.L01", "*.Lx01"]
    data_set = []
    ewf_files = get_ewf_files(root, patterns)
    for file_set in ewf_files:
        ewf_handle = pyewf.handle()
        file_name = pyewf.glob(file_set)
        ewf_handle.open(file_name)
        image_data = {'file_set': file_name[0]}
        image_data.update(get_header_info())
        image_data.update(get_hash_values())
        data_set.append(image_data)

    if 'csv' in args.t:
        csv_output(data_set, args.w)

    if 'json' in args.t:
        json_output(data_set)

    if 'xlsx' in args.x:
        xlsx_output(data_set, args.w)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Output EWF and LWF file data')
    parser.add_argument('-d', required=True, help='Top Level Directory to process', action='store')
    parser.add_argument('-o', required=True, help='Output Type: csv, xlsx, json',
                        choices=('csv','xlsx','json'), action='store')
    parser.add_argument('-w', required=False, help='Output Filename', action='store')

    args = parser.parse_args()

    if int(platform.python_version()[0]) < 3:
        raise Exception('This script requires python 3')
    else:
        main(args)

    '''print(pyewf.get_version())'''
