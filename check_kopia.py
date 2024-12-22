#!/usr/bin/env python3

import sys
import requests
import argparse


# Argument Parsing
parser = argparse.ArgumentParser(description="Query Kopia API to get backup status for Nagios monitoring")
parser.add_argument("-H", "--host",  metavar="HOST", dest="host", help="Host name or IP", required=True)
parser.add_argument("-p", "--port", metavar="PORT", type=int, dest="port", help="HTTP/HTTPS port to connect on. Default=51515", default=51515)
parser.add_argument("--ignore-cert", dest="ignore_cert", help="Ignore any TLS certificate warnings e.g. for self-signed cert.", action='store_true')
parser.add_argument("--http", dest="insecure", help="Use HTTP rather than https", action='store_true')

args = parser.parse_args()

# Verify parameters passed in

host = args.host
port = args.port
ignoressl = args.ignore_cert
if args.insecure:
    schema = "http"
else:
    schema = "https"


nagios_status_code = 3

# Run this function to output status and Exit
def result(message):
    global nagios_status_code
    print(message)
    sys.exit(nagios_status_code)


# TODO: implement SSL certificate ignore flag
res = requests.get(f"{schema}://{host}:{port}/api/v1/repo/status")
if res.status_code != 200:
    nagios_status_code = 3
    result(f"HTTP Error from API: {res.status_code}")


