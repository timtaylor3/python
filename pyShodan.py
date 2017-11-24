#!/usr/bin/env python

import argparse
import json
import shodan

def main(args):

    API_KEY = args.k

    api = shodan.Shodan(API_KEY)
    results = api.search(args.s)

    #print json.dumps(results, sort_keys=True, indent=4, separators=(',', ': '))
    for item in results['matches']:
        try:
            print 'IP: %s' % item['ip_str']
            print 'ISP: %s' % item['isp']
            print 'ASN: %s' % item['asn']
            print 'Product: %s' % item['product']
            print 'City: %s' % item['location']['city']
            print 'State: %s' % item['location']['region_code']
            print 'Zip Code: %s' % item['location']['postal_code']
            print 'Country: %s' % item['location']['country_name']
            print 'Country Code: %s' % item['location']['country_code']
            print 'Country Code: %s' % item['location']['country_code3']
            print 'Area Code: %s' % item['location']['area_code']
            print 'DMA Code: %s' % item['location']['dma_code']
            print 'Latitude: %s' % item['location']['latitude']
            print 'Longitude: %s' % item['location']['longitude']
            print 'Organization: %s' % item['org']
            print 'SSL Cert Org: %s' % item['ssl']['cert']['subject']['O']
            print 'SSL Cert CN: %s' % item['ssl']['cert']['subject']['CN']
            print 'Time Stamp: %s' % item['timestamp']

        except KeyError:
            pass

        except shodan.APIError, e:
            print 'Error: %s' % e

if __name__ == "__main__":
    parser = argparse.ArgumentParser('Search Shodan.')
    parser.add_argument('-s', required=True, help="Search Term")
    parser.add_argument('-k', required=True, help="Shodan API Key")
    args = parser.parse_args()

    main(args)



