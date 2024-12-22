#!/usr/bin/env python3

import sys
import requests
import argparse
import lxml.html


# Argument Parsing
parser = argparse.ArgumentParser(description="Query Kopia API to get backup status for Nagios monitoring")
parser.add_argument("-H", "--host",  metavar="HOST", dest="host", help="Host name or IP", required=True)
parser.add_argument("-p", "--port", metavar="PORT", type=int, dest="port", help="HTTP/HTTPS port to connect on. Default=51515", default=51515)
parser.add_argument("--ignore-cert", dest="verify_ssl", help="Ignore any TLS certificate warnings e.g. for self-signed cert.", action='store_false')
parser.add_argument("--http", dest="insecure", help="Use HTTP rather than https", action='store_true')

args = parser.parse_args()

# Verify parameters passed in

host = args.host
port = args.port
verify_ssl = args.verify_ssl
if args.insecure:
    schema = "http"
else:
    schema = "https"


status_detail = {}

# Run this function to output status and Exit
def result(status_code, message):
    print(message)
    sys.exit(status_code)


http_session = requests.Session()
if verify_ssl == False:
    http_session.verify = False
    requests.packages.urllib3.disable_warnings()

response = None
response = http_session.get(f"{schema}://{host}:{port}/")
if response.status_code != requests.codes.ok:
    result(3,f"HTTP Error when getting CSRF token: {response.status_code}\n{response.text.strip()}")

# Parse out <meta name="kopia-csrf-token" content="abcxyz"/> from <head> to get the CSRF token needed by the API calls
html_doc = lxml.html.document_fromstring(response.content)
csrf_element = html_doc.xpath("//meta[@name='kopia-csrf-token']")
if len(csrf_element) < 1:
    result(3,"Unable to parse CSRF token from HTTP response")
csrf_token = csrf_element[0].attrib['content']


# Now actually make API calls using the token

http_session.headers.update({"X-Kopia-Csrf-Token": csrf_token})

response = None
response = http_session.get(f"{schema}://{host}:{port}/api/v1/repo/status")
if response.status_code != requests.codes.ok:
    result(3,f"HTTP Error from API: {response.status_code}\n{response.text.strip()}")

status_detail['repo_connected'] = response.json()['connected']


# Logic to determine status/state
# 0 = OK
# 1 = Warning
# 2 = Critical
# 3 = Unknown

if not status_detail['repo_connected']:
    result(2,"Repository disconnected.")

# If we got here, then everything above is good - set status code to OK
status_message = f"OK: Repository Connnected"
result(0,status_message)


# Catch-all at the end.  We should never get here so if we did, then its unknown state (3)
sys.exit(3)
