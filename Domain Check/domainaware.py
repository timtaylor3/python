#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A dnstwist and/or URLCrazy wrapper for emailing security staff when possible typo sqatting/spear
phishing domains have been registered"""

"""
Requirements:
pip3 install python-whois
python3-yara
pip3 install selenium
phantomjs
"""

import json
import urllib.request
import urllib.error
import ssl
import whois
import time
import yara
from time import sleep
from configparser import ConfigParser
from argparse import ArgumentParser
from os import path, getcwd
from os.path import isfile
from subprocess import check_output, PIPE, CalledProcessError
from sys import stderr
from io import StringIO
from csv import DictReader, DictWriter
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.utils import COMMASPACE
from requests import get, post
from selenium import webdriver
from selenium.common.exceptions import (
    UnexpectedAlertPresentException,
    InsecureCertificateException,
    TimeoutException,
    WebDriverException)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.alert import Alert
import zipfile

__author__  = 'Tim Taylor'
__credit__  = ['Sean Whalen']

__version__ = '1.0.0'

HTTP_RESPONSES = {
    100: ('Continue', 'Request received, please continue'),
    101: ('Switching Protocols',
          'Switching to new protocol; obey Upgrade header'),

    200: ('OK', 'Request fulfilled, document follows'),
    201: ('Created', 'Document created, URL follows'),
    202: ('Accepted',
          'Request accepted, processing continues off-line'),
    203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
    204: ('No Content', 'Request fulfilled, nothing follows'),
    205: ('Reset Content', 'Clear input form for further input.'),
    206: ('Partial Content', 'Partial content follows.'),

    300: ('Multiple Choices',
          'Object has several resources -- see URI list'),
    301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
    302: ('Found', 'Object moved temporarily -- see URI list'),
    303: ('See Other', 'Object moved -- see Method and URL list'),
    304: ('Not Modified',
          'Document has not changed since given time'),
    305: ('Use Proxy',
          'You must use proxy specified in Location to access this '
          'resource.'),
    307: ('Temporary Redirect',
          'Object moved temporarily -- see URI list'),

    400: ('Bad Request',
          'Bad request syntax or unsupported method'),
    401: ('Unauthorized',
          'No permission -- see authorization schemes'),
    402: ('Payment Required',
          'No payment -- see charging schemes'),
    403: ('Forbidden',
          'Request forbidden -- authorization will not help'),
    404: ('Not Found', 'Nothing matches the given URI'),
    405: ('Method Not Allowed',
          'Specified method is invalid for this server.'),
    406: ('Not Acceptable', 'URI not available in preferred format.'),
    407: ('Proxy Authentication Required', 'You must authenticate with '
                                           'this proxy before proceeding.'),
    408: ('Request Timeout', 'Request timed out; try again later.'),
    409: ('Conflict', 'Request conflict.'),
    410: ('Gone',
          'URI no longer exists and has been permanently removed.'),
    411: ('Length Required', 'Client must specify Content-Length.'),
    412: ('Precondition Failed', 'Precondition in headers is false.'),
    413: ('Request Entity Too Large', 'Entity is too large.'),
    414: ('Request-URI Too Long', 'URI is too long.'),
    415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
    416: ('Requested Range Not Satisfiable',
          'Cannot satisfy request range.'),
    417: ('Expectation Failed',
          'Expect condition could not be satisfied.'),

    500: ('Internal Server Error', 'Server got itself in trouble'),
    501: ('Not Implemented',
          'Server does not support this operation'),
    502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
    503: ('Service Unavailable',
          'The server cannot process the request due to a high load'),
    504: ('Gateway Timeout',
          'The gateway server did not receive a timely response'),
    505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
}

def get_whois(rows):
    print('Adding whois data')
    count = len(rows)
    c = 0
    for row in rows:
        try:
            whois_data = json.load(StringIO(str(whois.whois(row['Domain']))))

            if type(whois_data['name']) == list:
                row.update({'Registrant': ', '.join(whois_data['name'])})
            else:
                row.update({'Registrant': whois_data['name']})

            if type(whois_data['registrar']) == list:
                row.update({'Registrar': ', '.join(whois_data['registrar'])})
            else:
                row.update({'Registrar': whois_data['registrar']})

            if type(whois_data['expiration_date']) == list:
                row.update({'Expires': ', '.join(whois_data['expiration_date'])})
            else:
                row.update({'Expires': whois_data['expiration_date']})

            if type(whois_data['updated_date']) == list:
                row.update({'Updated': ', '.join(whois_data['updated_date'])})
            else:
                row.update({'Updated': whois_data['updated_date']})

            if type(whois_data['creation_date']) == list:
                row.update({'Created': ', '.join(whois_data['creation_date'])})
            else:
                row.update({'Created': whois_data['creation_date']})

        except:
            print('Whois lookup on {} failed'.format(row['Domain']))
            row.update({'Registrant': 'Whois lookup failed'})

        c += 1
        print('{}, {} of {} whois lookup completed.'.format(row['Domain'], c, count))
        sleep(3)

    return rows


def dt_whois(domain, **kwargs):
    """Returns WHOIS data from DomainTools"""
    user_agent = "domainaware/{}".format(__version__)
    headers = {"User-Agent": user_agent}
    params = dict(api_username=kwargs["api_username"], api_key=kwargs["api_key"])
    url = "https://api.domaintools.com/v1/{}/whois".format(domain)
    if kwargs["parsed_whois"].lower() == "true":
        url += "/parsed"
    response = get(url, headers=headers, params=params)
    if response.status_code == 403:
        raise RuntimeError("DomainTools authentication failed")
    parsed_response = response.json()
    if "error" in parsed_response:
        error = parsed_response['error']['message']
        print("Warning: DomainTools error for domain {}: {}".format(domain, error), file=stderr)
        return dict()
    return response.json()["response"]


def get_row_domain(row):
    """Used as the key for sorting CSV rows by domain"""
    return row['Domain']


def convert_country(name):
    """Converts a country name from urlcrazy format to dnstwist format"""
    words = name.split(" ")
    for i in range(len(words)):
        words[i] = words[i].lower().title()
    name = " ".join(words)

    return name


def crazy_twist(crazy_row):
    """Converts a urlcrazy row to dnstwist format"""
    fuzzer_map = {
        "Character Omission": "Omission",
        "Character Repeat": "Repetition",
        "Character Swap": "Transposition",
        "Character Replacement": "Replacement",
        "Character Insertion": "Insertion",
        "Common Misspelling": "Misspelling",
        "Bit Flipping": "Bitsquatting",
        "Homoglyphs": "Homoglyph",
        "Wrong SLD": "Subdomain"
    }

    fuzzer = crazy_row["Typo Type"]
    if fuzzer in fuzzer_map:
        fuzzer = fuzzer_map[fuzzer]

    twist_row = {
        "Fuzzer": fuzzer,
        "Domain": crazy_row["Typo"],
        "A": crazy_row["DNS-A"],
        "MX": crazy_row["DNS-MX"]
    }

    if crazy_row['Country-A']:
        twist_row['Country'] = convert_country(crazy_row["Country-A"])

    # Sometimes the URLCrazy MX row is actually the TLD row :\
    if twist_row["MX"] == twist_row["Domain"].split(".")[-1] \
            or twist_row["MX"] == twist_row["Domain"].split(".", 1)[-1] \
            or twist_row["MX"] == twist_row["Domain"].split(".", 2)[-1]:
        twist_row["MX"] = ''

    twist_row.update({'Source': 'URLCrazy'})

    return twist_row


def twist_query(dnstwist_path, domain):
    """Query dnstwist"""
    rows = []
    dt_args = [dnstwist_path, '-bgrj', '--nameservers', '208.67.222.220', domain]
    output = check_output(dt_args, universal_newlines=True, stderr=PIPE)
    dnstwist_csv = json.load(StringIO(str(output)))

    for row in dnstwist_csv:
        row = validate_json(row)

        standard_row = dict(Fuzzer=row["fuzzer"],
                            Domain=row["domain-name"],
                            A=row["dns-a"],
                            AAAA=row["dns-aaaa"],
                            MX=row["dns-mx"],
                            NS=row["dns-ns"],
                            Country=row["geoip-country"],
                            Banner=row["banner-http"],
                            Source='DNSTwist'
                            )

        rows.append(standard_row)

    return rows


def validate_json(row):
    # Validate and clean up row
    if 'dns-a' in row:
        dns_a = ', '.join(row["dns-a"])
        row.update({'dns-a': dns_a})
    else:
        row.update({'dns-a': ''})

    if 'dns-aaaa' in row:
        dns_aaaa = ', '.join(row["dns-aaaa"])
        row.update({'dns-aaaa': dns_aaaa})
    else:
        row.update({'dns-aaaa': ''})

    if 'dns-mx' in row:
        dns_mx = ', '.join(row["dns-mx"])
        row.update({'dns-mx': dns_mx})
    else:
        row.update({'dns-mx': ''})

    if 'dns-ns' in row:
        dns_ns = ', '.join(row["dns-ns"])
        row.update({'dns-ns': dns_ns})
    else:
        row.update({'dns-ns': ''})

    if 'geoip-country' not in row:
        row.update({'geoip-country': ''})

    if 'ssdeep-score' not in row:
        row.update({'ssdeep-score': ''})

    if 'banner-http' not in row:
        row.update({'banner-http': ''})

    return row


def crazy_query(urlcrazy_path, domain, attempt=1):
    """Query URLCrazy"""
    max_attempts = 4
    rows = []
    dt_args = [urlcrazy_path, '-f', 'csv', domain]
    try:
        output = check_output(dt_args, universal_newlines=True, stderr=PIPE)
        output = str(output)
        output = output.replace('\0', '')
        # URLCrazy frequently returns bad output, so keep trying :\
    except (UnicodeDecodeError, ProcessLookupError, ChildProcessError):
        attempt += 1
        if attempt > max_attempts:
            print("Warning: Failed to parse URLCrazy output for {}".format(domain), file=stderr)
            return []
        return crazy_query(urlcrazy_path, domain, attempt)
    except CalledProcessError:
        # Sometimes URLCrazy considers valid domains invalid and exits with 1
        print("Warning: URLCrazy does not recognize {} as a valid domain".format(domain), file=stderr)
        return []
    urlcrazy_csv = DictReader(StringIO(output, newline=''))
    for row in urlcrazy_csv:
        rows.append(crazy_twist(row))

    return rows


def add_dt(rows, **kwargs):
    """Add WHOIS information from DomainTools to the CSV rows"""
    for row in rows:
        whois = dt_whois(row['Domain'], **kwargs)
        if 'registrant' in whois:
            row["Registrant"] = whois["registrant"]
        if 'registration' in whois:
            if 'registrar' in whois['registration']:
                row["Registrar"] = whois['registration']["registrar"]
            if 'created' in whois['registration']:
                row["Created"] = whois['registration']["created"]
            if 'updated' in whois['registration']:
                row["Updated"] = whois['registration']["updated"]
            if 'expires' in whois['registration']:
                row["Expires"] = whois['registration']["expires"]
        sleep(1)

    return rows


def add_vt(rows, **kwargs):
    """Add VirusTotal Data"""
    vt_sleep_time = 16
    count = len(rows)

    print('Submitting domains to VT')
    c = 0
    for row in rows:
        scan_id = submit_domain(row['Domain'], **kwargs)
        row.update({'Scan ID': scan_id})
        time.sleep(vt_sleep_time)
        c += 1
        print('Submitting {} ({} of {}) to Virus Total completed'.format(row['Domain'], c, count))

    print('Retrieving VT Results')

    c = 0
    for row in rows:

        if row.get('scan_id', {}) != '':
            permalink, ratio = vt_query(row['Scan ID'], **kwargs)
            row.update({'VT Ratio': ratio})
            row.update({'VT Permalink': permalink})

        time.sleep(vt_sleep_time)
        c += 1
        print('Retrieving scan {} of {} Virus Total scans completed'.format(c, count))

    return rows


def submit_domain(domain, **kwargs):
    vt_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    vt_response = ''
    scan_id = ''

    parameters = {'apikey': kwargs['vt_api_key'], 'url': domain}

    try:
        response = post(vt_url, data=parameters)
        vt_response = response.json()

        if vt_response.get('response_code') == 1:
            scan_id = vt_response.get('scan_id', {})

        else:
            print(vt_response)

    except json.decoder.JSONDecodeError:
        print('JSON Decode Error submitting {}'.format(domain))
        print(vt_response)

    except AttributeError:
        print(type(vt_response))
        print(vt_response)

    return scan_id


def vt_query(scan_id, **kwargs):
    permalink = ''
    ratio = ''
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    vt_response = ''
    av_hits = ''

    parameters = {'apikey': kwargs['vt_api_key'], 'resource': scan_id}
    headers = {"Accept-Encoding": "gzip, deflate",
               "User-Agent": "gzip,  My Python requests library example client or username"}

    try:
        response = post(url, params=parameters, headers=headers)

        vt_response = response.json()

        if vt_response.get('response_code') != 1:
            permalink = vt_response.get('verbose_msg')
            ratio = vt_response.get('response_code')
        else:
            ratio = vt_response.get('response_code')
            av_hits = vt_response.get('positives', {})
            total_engines = vt_response.get('total', {})

            permalink = vt_response.get('permalink', {})
            av_hits = str(av_hits)
            total_engines = str(total_engines)
            ratio = ' of '.join([av_hits, total_engines])

    except json.decoder.JSONDecodeError:
        print('Json Decode Error querying VT: {}'.format(scan_id))
        print(vt_response)
        permalink = 'Json Decode Error querying VT: {}'.format(scan_id)
        ratio = 'Error'

    except AttributeError:
        print(type(vt_response))
        print(vt_response)

    except Exception as e:
        print(str(e))

    return permalink, ratio


def find_new_domains(tool_paths, my_domains_path, known_domains_path, yara_rules, **kwargs):
    """"Returns suspicious domain information as a list of dictionaries"""
    known_domains = set()
    rows = []
    with open(known_domains_path, 'r') as known_domains_file:
        known_domains_csv = DictReader(known_domains_file)
        for row in known_domains_csv:
            known_domains.add(row["Domain"])

    with open(my_domains_path, 'rU') as my_domains:
        for my_domain in my_domains:
            my_domain = my_domain.strip().lower()
            known_domains.add(my_domain)

            print('Calculating domains for {}'.format(my_domain))

            if tool_paths["dnstwist"]:
                for row in twist_query(tool_paths["dnstwist"], my_domain):
                    if row['Domain'] not in known_domains:
                        rows.append(row)
                        known_domains.add(row['Domain'])

            if tool_paths["urlcrazy"]:
                for row in crazy_query(tool_paths["urlcrazy"], my_domain):
                    if row["A"] == '' and row["MX"] == '':
                        continue
                    if row['Domain'] not in known_domains:
                        rows.append(row)
                        known_domains.add(row['Domain'])

    if kwargs["api_username"] and kwargs["api_key"]:
        rows = add_dt(rows, **kwargs)

    else:
        rows = get_whois(rows)

    rows = add_html_analysis(rows, yara_rules)
    '''
    if kwargs["vt_username"] and kwargs["vt_api_key"]:
        rows = add_vt(rows, **kwargs)
    '''
    rows = get_screen_captures(rows)

    return sorted(rows, key=get_row_domain)


def get_screen_captures(rows):
    count = len(rows)
    c = 0
    url = ''

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--dns-prefetch-disable")
    chrome_driver = webdriver.Chrome(chrome_options=chrome_options)
    chrome_driver.set_page_load_timeout(30)
    chrome_driver.set_script_timeout(30)
    alert = Alert(chrome_driver)
    chrome_output_file = ''
    chrome_base64_data = ''
    chrome_page_title = ''
    chrome_current_url = ''

    for row in rows:
        c+=1
        try:
            url = ".".join(['http://www', row['Domain']])
            out_file = ".".join([row['Domain'], 'png'])
            chrome_output_file = '_'.join(['Chrome', out_file])
            chrome_driver.get(url)
            #chrome_driver.save_screenshot(chrome_output_file)
            chrome_base64_data = chrome_driver.get_screenshot_as_base64()
            chrome_page_title = chrome_driver.title
            chrome_current_url = chrome_driver.current_url

            print('Encoding {} into Base64 ({} of {})'.format(chrome_output_file, c, count))

            row.update({'Chrome Image': chrome_output_file})
            row.update({'Chrome Base64': chrome_base64_data})
            row.update({'Chrome Page Title': chrome_page_title})
            row.update({'Chrome Current URL': chrome_current_url})
            row.update({'Chrome Alert Text': ''})

        except UnexpectedAlertPresentException as e:
            print(e.__str__())
            print(url)

            row.update({'Chrome Image': 'Popup Error: {}'.format(url)})
            row.update({'Chrome Base64': 'Popup Error: {}'.format(url)})
            row.update({'Chrome Page Title': 'Popup Error: {}'.format(url)})
            row.update({'Chrome Current URL': 'Popup Error: {}'.format(url)})
            pass

        except InsecureCertificateException as e:
            print(e.__str__())
            row.update({'Chrome Image': ': '.join(['Insecure Certificate Exception', url])})
            row.update({'Chrome Base64': 'Insecure Certificate Exception'})
            row.update({'Chrome Page Title': 'Insecure Certificate Exception'})
            row.update({'Chrome Current URL': 'Insecure Certificate Exception'})
            continue

        except TimeoutException as e:
            print(e.__str__())
            print(url)
            row.update({'Chrome Image': ': '.join(['Timeout Exception', url])})
            row.update({'Chrome Base64': 'Timeout Exception'})
            row.update({'Chrome Page Title': 'Timeout Exception'})
            row.update({'Chrome Current URL': 'Timeout Exception'})
            continue

        except WebDriverException as e:
            print(e.__str__())
            row.update({'Chrome Image': ': '.join(['WebDriver Exception', url])})
            row.update({'Chrome Base64': 'WebDriver Exception'})
            row.update({'Chrome Page Title': 'WebDriver Exception'})
            row.update({'Chrome Current URL': 'WebDriver Exception'})

        except ConnectionRefusedError as e:
            print('Connection Refused: {}'.format(url))
            row.update({'Chrome Image': 'Connection Refused'})
            row.update({'Chrome Base64': 'Connection Refused'})
            row.update({'Chrome Page Title': 'Connection Refused'})
            row.update({'Chrome Current URL': 'Connection Refused'})
            pass

    chrome_driver.quit()

    return rows


def add_html_analysis(rows, yara_rules):
    print('Adding HTML analysis')
    hits = 0
    r_tags = ''
    url = ''
    c = 0
    count = len(rows)

    if isfile(yara_rules):
        rules = yara.compile(yara_rules)
    else:
        hits = -1

    for row in rows:

        url = ".".join(['http://www', row["Domain"]])

        text, header, returned_url, response_code, response_message = get_html(url)

        if rules:
            hits, r_tags = yara_search(rules, text)
            r_tags = ', '.join(r_tags)

        row.update({'Yara Hits': hits})
        row.update({'Yara Tags': r_tags})
        row.update({'Header': header})
        row.update({'Returned URL': returned_url})
        row.update({'HTML Response Code': response_code})
        row.update({'HTML Response Message': response_message})
        c += 1
        print('{} Web site data added: {} of {}'.format(row["Domain"], c, count))

    return rows


def get_html(url):
    text = ''
    returned_url = ''
    response_code = ''
    response_message = ''
    header = ''

    try:
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req)
        html = response.read()
        returned_url = response.geturl()
        response_code = response.getcode()
        response_message = HTTP_RESPONSES[response.getcode()]

        response_message = ', '.join(response_message)

        header = str(response.info())

        text = html.decode('utf8')

    except urllib.error.URLError as e:
        if hasattr(e, 'reason'):

            if 'Errno 111' in str(e.reason):
                response_code = '111'
                response_message = 'Connection refused'
                pass

            elif 'Errno 104' in str(e.reason):
                response_code = '104'
                response_message = 'Connection reset by peer'
                pass

            elif 'Errno -2' in str(e.reason):
                response_code = '-2'
                response_message = 'Name or service not known'
                pass

            elif 'Forbidden' in str(e.reason):
                response_code = 'UNK'
                response_message = 'Forbidden'
                pass

            else:
                print('URL: {}, Error Code: {}'.format(url, e.reason))
                response_code = 'UNK'
                response_message = str(e.reason)
                pass

        elif hasattr(e, 'code'):
            response_code = e.code
            response_message = HTTP_RESPONSES[e.code]

    except ssl.CertificateError as e:
        response_code = 'SSL'
        response_message = str(e)
        pass

    except UnicodeDecodeError as e:
        print(str(e))

    except ConnectionError as e:
        print(str(e))

    return text, header, returned_url, response_code, response_message


def yara_search(rules, text):
    hits = 0
    r_tags = ''

    matches = rules.match(data=text)

    if matches:
        hits = len(matches[0].strings)
        r_tags = matches[0].tags

    return hits, r_tags


def generate_output(results, config_directory, output_path):
    """"Writes output files"""
    lines = []
    # write out results
    # this file will only contain the header if there are no new results

    print('Writing Output file')

    with open(output_path, 'w') as outfile:

        fieldnames = ['Domain', 'Fuzzer', 'Source',
                      'Registrant', 'Registrar', 'Created', 'Updated', 'Expires', 
                      'A', 'AAAA', 'MX', 'NS', 'Country', 
                      'Banner', 
                      'Scan ID', 'VT Ratio', 'VT Permalink', 
                      'Yara Hits', 'Yara Tags', 
                      'Header', 'Returned URL', 
                      'HTML Response Code', 'HTML Response Message']

        writer = DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            lines.append(row['Domain'])
            writer.writerow(row)

    try:
        with open(path.join(config_directory, "last_domains"), "w") as last_domains_file:
            last_domains_file.write("\n".join(lines))

    except ValueError:
        print('Value Error')


def output_html_file(results, config_directory, output_path):

    with open(output_path, 'w') as html_file:
        html_file.write('<!DOCTYPE html>')
        html_file.write('<html>')
        html_file.write('<head>')
        html_file.write('<style>')
        html_file.write('table, th, td {')
        html_file.write('       border: 1px solid black;')
        html_file.write('       border-collapse: collapse; }')
        html_file.write('th, td {')
        html_file.write('       padding: 5px;')
        html_file.write('       text-align: left; }')
        html_file.write('</style>')
        html_file.write('</head>')

        html_file.write('<body>')
        for row in results:
            html_file.write('<table>')

            html_file.write(''.join(['<tr><th>Checked Domain Name</th><td>', row['Domain'], '</td>']))

            html_file.write('<tr><th>Chrome Web Page Image</th>')
            pic_link = ''.join(['<img alt="', row['Chrome Image'], '" src="data:image/png;base64,', row['Chrome Base64'], '" />'])
            html_file.write(''.join(['<td>', pic_link, '</td></tr>']))
            html_file.write(''.join(['<tr><th>Chrome Page Title</th><td>', row['Chrome Page Title'], '</td></tr>']))
            html_file.write(''.join(['<tr><th>Chrome Current URL</th><td>', row['Chrome Current URL'], '</td></tr>']))

            html_file.write('<tr><th colspan="2">Whois Information</th></tr>')
            html_file.write(''.join(['<tr><th>Registrant</th><td>', str(row['Registrant']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>Registrar</th><td>', str(row['Registrar']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>Created</th><td>', str(row['Created']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>Updated</th><td>', str(row['Updated']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>Expires</th><td>', str(row['Expires']), '</td></tr>']))

            html_file.write('<tr><th colspan="2">DNS Information</th></tr>')

            html_file.write(''.join(['<tr><th>A</th><td>', str(row['A']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>AAAA</th><td>', str(row['AAAA']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>MX</th><td>', str(row['MX']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>NS</th><td>', str(row['NS']), '</td>']))
            html_file.write(''.join(['<tr><th>Country</th><td>', str(row['Country']), '</td></tr>']))
            '''
            html_file.write('<tr><th colspan="2">VirusTotal Information</th></tr>')
            html_file.write(''.join(['<tr><th>VT Ratio</th><td>', row['VT Ratio'], '</td></tr>']))
            html_file.write(''.join(['<tr><th>VT Permalink</th><td>', row['VT Permalink'], '</td></tr>']))
            '''
            html_file.write('<tr><th colspan="2">Yara Information</th></tr>')
            html_file.write(''.join(['<tr><th>Yara Hits</th><td>', str(row['Yara Hits']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>Yara Tags</th><td>', row['Yara Tags'], '</td></tr>']))

            html_file.write('<tr><th colspan="2">HTML Information</th></tr>')
            html_file.write(''.join(['<tr><th>Banner</th><td>', row['Banner'], '</td></tr>']))
            html_file.write(''.join(['<tr><th>Header</th><td>', row['Header'], '</td></tr>']))
            html_file.write(''.join(['<tr><th>Returned URL</th><td>', row['Returned URL'], '</td></tr>']))
            html_file.write(''.join(['<tr><th>Response Code</th><td>', str(row['HTML Response Code']), '</td></tr>']))
            html_file.write(''.join(['<tr><th>Response Message</th><td>', row['HTML Response Message'], '</td></tr>']))

            html_file.write('</table>')
            html_file.write('<br><br>')

        html_file.write('</html>')
        html_file.write('</body>')


def zip_file(html_file):

    zip_name = '.'.join([html_file, 'zip'])
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_LZMA) as myzip:
        myzip.write(html_file)

    return zip_name


def send_mail(**kwargs):
    """Sends an email message"""
    msg = MIMEMultipart()
    msg["From"] = kwargs["from"]
    msg["To"] = kwargs['to']
    msg["Subject"] = kwargs["subject"]

    msg.attach(MIMEText(kwargs['body']))

    if "files" in kwargs:
        files = kwargs['files']
    else:
        files = None

    for f in files or []:
        with open(f, "rb") as fil:
            msg.attach(MIMEApplication(
                fil.read(),
                Content_Disposition='attachment; filename="{}"'.format(path.basename(f)),
                Name=path.basename(f)
            ))

    mail_server = SMTP(kwargs["host"], kwargs["port"])
    mail_server.ehlo()
    try:
        mail_server.starttls()
    except:
        pass  # Try STARTTLS, but continue if it fails
    mail_server.ehlo()
    if kwargs["username"]:
        mail_server.login(kwargs["username"], kwargs["password"])
    mail_server.sendmail(kwargs["from"], kwargs["to"].split(COMMASPACE), msg.as_string())
    mail_server.quit()


def mail_report(output_file_path, **kwargs):
    """Mail the report"""
    num_lines = 0
    num_domains = 0
    with open(output_file_path, 'rbU') as output_file:
        for _ in output_file:
            num_lines += 1
            num_domains = num_lines - 1  # Ignore CSV header in count
    if num_domains > 0:
        zip_name = zip_file(output_file_path)
        kwargs["files"] = [zip_name]
        kwargs["body"] = kwargs["new_results_body"]
        send_mail(**kwargs)


def main():
    """Called when the module is executed rather than imported"""
    parser = ArgumentParser(prog='domainaware',
                            description=__doc__)
    parser.add_argument('-c', '--config',
                        help='Directory location for required config files; defaults to the current working directory',
                        default=getcwd(),
                        required=False)
    parser.add_argument('-o', '--output', help='Path to output to; defaults to results.html', default='results.html',
                        required=False)
    parser.add_argument('-m', '--email', help='Email results upon completion; defaults to False', action="store_true",
                        default=False, required=False)

    args = parser.parse_args()

    if not path.isdir(args.config):
        print("ERROR! Specified configuration directory {} does not exist!".format(args.config), file=stderr)
        exit(-1)

    config_file_path = path.join(args.config, "settings.cfg")
    if not path.exists(config_file_path):
        print("ERROR! {} does not exist!".format(config_file_path), file=stderr)
        exit(-1)

    output_path = args.output
    my_domains_path = path.join(args.config, 'mydomains.csv')
    known_domains_path = path.join(args.config, 'knowndomains.csv')
    yara_rules_path = path.join(args.config, 'yara-rules.txt')

    config = ConfigParser(allow_no_value=True)
    config.read([config_file_path])

    paths_config = dict(config.items("paths"))
    email_config = dict(config.items("email"))
    email_config["results_file"] = output_path
    dt_config = dict(config.items("domaintools"))
    vt_config = dict(config.items("virustotal"))

    last_domains_path = path.join(args.config, "last_domains")
    stale = False
    if path.exists(last_domains_path):
        with open(last_domains_path) as last_domains_file:
            last_domains = last_domains_file.readlines()
        with open(known_domains_path) as known_csv:
            csv_reader = DictReader(known_csv)
            known_domains = []
            for csv_row in csv_reader:
                known_domains.append(csv_row["Domain"])
            for domain in last_domains:
                if domain not in known_domains:
                    stale = True
                    break
    if stale:
        if args.email:
            email_config["body"] = email_config["stale_body"]
            send_mail(**email_config)
            print("ERROR! Domains from the last run have not been added to knowndomains.csv. Exiting...", file=stderr)
            exit(2)

    results = find_new_domains(paths_config, my_domains_path, known_domains_path, yara_rules_path, **dt_config,
                               **vt_config)

    #generate_output(results, args.config, output_path)
    output_html_file(results, args.config, output_path)

    if args.email:
        mail_report(args.output, **email_config)


if __name__ == "__main__":
    main()