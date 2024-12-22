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
parser.add_argument("--basic-auth", dest="http_basic_auth", help="Authenticate with username and password (HTTP Basic Auth)", action='store_true')
parser.add_argument("--user",  metavar="USERNAME", dest="username", help="Kopia Login Username (if using HTTP basic auth)")
parser.add_argument("--pass",  metavar="PASSWORD", dest="password", help="Kopia Login Password (if using HTTP basic auth)")


args = parser.parse_args()

# Verify parameters passed in

host = args.host
port = args.port
auth = None
verify_ssl = args.verify_ssl
if args.insecure:
    schema = "http"
else:
    schema = "https"


# Authentiction option validation
if args.http_basic_auth:
    if not args.username or not args.password:
        print("Missing username/password with HTTP basic auth enabled")
        sys.exit(-1)
    else:
        username = args.username
        password = args.password
        auth = "basic"

if (args.username or args.password) and not args.http_basic_auth:
    print("Username/Password provided, but HTTP Basic auth not enabled. Ensure --basic-auth is being used on the command")
    sys.exit(-1)


status_detail = {}

# Run this function to output status and Exit
def result(status_code, message):
    print(message)
    sys.exit(status_code)

# Setup HTTP Session and parameters
http_session = requests.Session()
if verify_ssl == False:
    http_session.verify = False
    requests.packages.urllib3.disable_warnings()

if auth == "basic":
    http_session.auth = requests.auth.HTTPBasicAuth(username, password)

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
