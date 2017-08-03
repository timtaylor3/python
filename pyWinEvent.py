#!/usr/bin/env python
##################################################################
#  Tested on SIFT using Python2.7 and Python3.4.3
#  SIFT3 requires Python3 filemagic to be installed
#  Written by Tim Taylor, timtaylor3@yahoo.com
#  Use at your own risk, this needs work.
#  TODO:  Output using csv module
#  TODO:  Output only one Logon ID field
#  Look at Will Ballenthin python-evtx modules and scripts, maybe there is a better way
#  Maybe use dict/json to capture all fields before and then output as needed
#  Need a json output for a ELK Stack.
##################################################################
import argparse
from datetime import datetime
import magic
import os
import subprocess

def run_cmd(cmd, inShell=True, inData=None):
    """
    Run a system command.  The input must be a list.
    """
    response = ''
    stderr = ''
    stdout = ''

    try:
        response = subprocess.Popen(cmd, stdin=inData,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    shell=inShell
                                    )
        response.wait()


    except CalledProcessError as e:
        return e.output

    finally:
        return stdout


def process_logoff_file(outfile, temp):
    out_line = ""
    with open(temp, "r") as file:
        for line in file:
            line = line.replace('\n', '') + ' '
            line = ' '.join(line.split())


def process_logoff_line(line, outline, outfile):
    if line.startswith('Audit'):
        outline = audit_parsing(line)

    elif line.startswith('SecurityID'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Account Name'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Account Domain'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Logon ID'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Logon Type'):
        outline = outline + line.split(":")[1].strip(' ')
        output_line(outfile, outline)
        outline = ''
    return outline


def process_logon_file(outfile, temp):
    out_line = ""
    with open(temp, "r") as file:
        for line in file:
            line = line.replace('\n', '') + ' '
            line = ' '.join(line.split())

            out_line = process_logon_line(line, out_line, outfile)

def process_logon_line(line, outline, outfile):
    if line.startswith('Audit'):
        outline = audit_parsing(line)

    elif line.startswith('SecurityID') and 'NULL SID' not in line:
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Account Name'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Account Domain'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Logon ID'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Logon Type'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Logon GUID'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Workstation Name:'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Source Network Address:'):
        outline = outline + line.split(":")[1].strip(' ') + ', '

    elif line.startswith('Source Port:'):
        outline = outline + line.split(":")[1].strip(' ')
        output_line(outfile, outline)
        outline = ''

    return outline


def audit_parsing(line):
    buildline = line.split(',')
    dt_obj = datetime.strptime(buildline[1],  '%d/%m/%Y %I:%M:%S %p')
    dt = dt_obj.strftime('%Y%m%d, %H:%M')
    outline = buildline[0] + ', ' + dt + ', ' + buildline[2] + ', ' + buildline[3] + ', ' + buildline[4]+ ', ' + buildline[5] + '", '
    return outline

def output_line(outfile, line):
    with open(outfile, "a") as file:
        print(line)


def main(args):
    top_dir = args.d
    outfile = topdir + '.csv'
    temp_logon = topdir + '-logon.tmp'
    temp_logoff = topdir + '-logoff.tmp'
    response = ''
    '''Walk the directory and get the file name and file type'''
    for root, directory, files in os.walk(top_dir):
        for file in files:
            fname = os.path.join(root, file)
            try:
                '''python2'''
                file_type = magic.from_file(fname)
            except:
                '''python3'''
                with magic.Magic() as m:
                    file_type = m.id_filename(fname)

            if file_type.startswith("ASCII") or file_type.startswith('UTF-8'):
                cmd = 'grep -A8 -h "Microsoft-Windows-Security-Auditing,4634" {} >> {}'.format(fname, temp_logoff)
                response = run_cmd([cmd])
                cmd = 'grep -A24 -h "Microsoft-Windows-Security-Auditing,4624" {} >> {}'.format(fname, temp_logon)
                response = run_cmd([cmd])


            else:
                print('Error determining the type for {}. File type was {}'.format(fname, file_type))

            if response != '':
                print(response)

    print('Creating the output file: {}'.format(outfile))

    header = 'Audit, Date, Time, Log Source, Event ID, Description, Security ID, Account Name, Account Domain, Logon ID, Logon Type, Security ID, Account Name, Account Domain, Logon ID, Workstation Name, Source Network Address, Source Port'
    output_line(outfile, header)
    process_logoff_file(outfile, temp_logoff)
    process_logon_file(outfile, temp_logon)

    try:
        os.remove(temp_logon)
        os.remove(temp_logoff)

    except OSError as e:
        print(e.output)

    finally:
        exit('Finished')


if __name__ == "__main__":
    parser = argparse.ArgumentParser('Parse logon/logoff from Windows Event logs exported as csv.')
    parser.add_argument('-d', required=True, help='Source Directory')
    args = parser.parse_args()

    if args.d is not None:
        main(args)
    else:
        parser.print_help()
