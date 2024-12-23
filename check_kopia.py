#!/usr/bin/env python3

import sys
import argparse
from datetime import datetime,timezone,timedelta

import requests
import lxml.html
import dateutil.parser


# Argument Parsing
parser = argparse.ArgumentParser(description="Query Kopia API to get backup status for Nagios monitoring")
parser.add_argument("-w", metavar="HOURS", type=int, dest="warn_thresh", help="Warning threshold for missed snapshots", required=True)
parser.add_argument("-c", metavar="HOURS", type=int, dest="crit_thresh", help="Critical threshold for missed snapshots", required=True)
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

delta_hours_warning = args.warn_thresh
delta_hours_critical = args.crit_thresh


# Setup dict to store the parsed data we gather for analysis
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

# Get Repo connected status
response = None
response = http_session.get(f"{schema}://{host}:{port}/api/v1/repo/status")
if response.status_code != requests.codes.ok:
    result(3,f"HTTP Error from API: {response.status_code}\n{response.text.strip()}")

status_detail['repo_connected'] = response.json()['connected']

# Get snapshot status
response = None
response = http_session.get(f"{schema}://{host}:{port}/api/v1/sources")
if response.status_code != requests.codes.ok:
    result(3,f"HTTP Error from API: {response.status_code}\n{response.text.strip()}")

sources = response.json()['sources']

status_detail['next_snapshots'] = []

for source in sources:
    # Skip any manually scheduled snapshots with no next snapshot time
    if "nextSnapshotTime" not in source:
        continue

    next_snapshot_datetime = dateutil.parser.isoparse(source['nextSnapshotTime'])
    next_snapshot_username = source['source']['userName']
    next_snapshot_host = source['source']['host']
    next_snapshot_path = source['source']['path']

    next_snapshot_dict = { 
            "username": next_snapshot_username, 
            "host": next_snapshot_host, 
            "path": next_snapshot_path, 
            "time_next": next_snapshot_datetime
    }
    status_detail['next_snapshots'].append(next_snapshot_dict)


# Logic to determine status/state
# 0 = OK
# 1 = Warning
# 2 = Critical
# 3 = Unknown

# Connected check
if not status_detail['repo_connected']:
    result(2,"Repository disconnected.")

late_snapshots = []
time_now = datetime.now(timezone.utc)

for source in status_detail['next_snapshots']:
    if timedelta(hours = delta_hours_critical * -1) > (source['time_next'] - time_now):
        # Critical
        late_snapshot_dict = source
        late_snapshot_dict['severity'] = "critical"
        late_snapshots.append(late_snapshot_dict)
        continue

    if timedelta(hours = delta_hours_warning * -1) > (source['time_next'] - time_now):
        # Warning
        late_snapshot_dict = source
        late_snapshot_dict['severity'] = "warning"
        late_snapshots.append(late_snapshot_dict)
        continue

# Determine if any snapshots are late. Raise the error level to the worst if some are warn and some crit
if len(late_snapshots) > 0:
    status_message = ""

    critical_count = len([snapshot for snapshot in late_snapshots if snapshot['severity']=="critical" ])
    warning_count  = len([snapshot for snapshot in late_snapshots if snapshot['severity']=="warning" ])

    # Any critical items mean we return critical(2).  Otherwise its all warnings
    if critical_count > 0:
        overall_severity = 2
    else:
        overall_severity = 1
    
    # Summary output if there are more than two out of sync to keep the output short
    if critical_count + warning_count > 2:
        status_message = "Multiple snapshots are late. "

        if critical_count > 0 and warning_count > 0:
            status_message += f"{critical_count} more than {delta_hours_critical} {'hours'}; {warning_count} more than delta_hours_warning {'hours'}"
        elif critical_count > 0:
            status_message += f"{critical_count} more than {delta_hours_critical} {'hours'}"
        else:
            status_message += f"{warning_count} more than {delta_hours_warning} {'hours'}"

        result(overall_severity,status_message)

    # Otherwise we can be verbose about which ones exactly
    status_message = "Snapshots late:"
    for snapshot in late_snapshots:
        snapshot_desc = f"{snapshot['username']}@{snapshot['host']}:{snapshot['path']}"
        if snapshot['severity'] == "critical":
            snapshot_lateness = f"{delta_hours_critical} {'hours'} late"
        else:
            snapshot_lateness = f"{delta_hours_warning} {'hours'} late"

        status_message += " " + snapshot_desc + " - " + snapshot_lateness + ";"

    result(overall_severity,status_message)



# If we got here, then everything above is good - set status code to OK
status_message = f"OK: Repository Connnected"
result(0,status_message)


# Catch-all at the end.  We should never get here so if we did, then its unknown state (3)
sys.exit(3)
