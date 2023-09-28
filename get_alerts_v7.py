"""Retrieve CB Analytics alert data and save to a json file.
"""

import argparse
import json
import requests
import sys
import time


def get_environment(environment):
    """Function to get the required environment to build a Base URL. More info
    about building a Base URL can be found at
    https://developer.carbonblack.com/reference/carbon-black-cloud/authentication/#building-your-base-urls

    rtype: string
    """
    if environment == "EAP1":
        return "https://defense-eap01.confer.deploy.net"
    elif environment == "PROD01":
        return "https://dashboard.confer.net"
    elif environment == "PROD02":
        return "https://defense.conferdeploy.net"
    elif environment == "PROD05":
        return "https://defense-prod05.conferdeploy.net"
    elif environment == "PROD06":
        return "https://defense-eu.conferdeploy.net"
    elif environment == "PRODNRT":
        return "https://defense-prodnrt.conferdeploy.net"
    elif environment == "PRODSYD":
        return "https://defense-prodsyd.conferdeploy.net"
    elif environment == "PRODUK":
        return "https://ew2.carbonblack.vmware.com"
    elif environment == "GOVCLOUD":
        return "https://gprd1usgw1.carbonblack-us-gov.vmware.com"


def build_base_url(environment, org_key):
    """Build the base URL

    rtype: string
    """

    environment = get_environment(environment)

    return f"{environment}/api/alerts/v7/orgs/{org_key}/alerts/_search"


def main():
    """Function to parse arguments and retrieve the alert results"""

    parser = argparse.ArgumentParser(prog="get_alerts_v7.py", description="Query VMware Carbon Black Cloud for v7 alert data.")
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-p", "--project", required=True, help="Project Name")
    requiredNamed.add_argument("-e", "--environment", required=True, default="PROD05",
                               choices=["EAP1", "PROD01", "PROD02", "PROD05", "PROD06", "PRODNRT", "PRODSYD"],
                               help="Environment for the Base URL")
    requiredNamed.add_argument("-d", "--days", default=7, help="Time range in days to query.")
    requiredNamed.add_argument("-o", "--org_key", required=True, help="Org key (found in your product console under \
                              Settings > API Access > API Keys)")
    requiredNamed.add_argument("-i", "--api_id", required=True, help="API ID")
    requiredNamed.add_argument("-s", "--api_secret", required=True, help="API Secret Key")
    parser.add_argument("-w", "--watchlist", action='store_true', help="Retrieve WATCHLIST hits instead of CB_ANALYTICS alerts")
    args = parser.parse_args()

    URL = build_base_url(args.environment, args.org_key)
    AUTH_TOKEN = f"{args.api_secret}/{args.api_id}"

    payload = {
        "criteria": {
            "minimum_severity": "1",
            "device_target_value": [
                "LOW",
                "MEDIUM",
                "HIGH",
                "MISSION_CRITICAL"
            ],
            "workflow_status": [
                "OPEN",
                "IN_PROGRESS",
                "CLOSED"
            ],
            "type": [
                "CB_ANALYTICS"
            ]
        },
        "exclusions": {},
        "time_range": {
            "range": f"-{args.days}d"
        },
        "sort": [
            {
                "field": "backend_timestamp",
                "order": "DESC"
            }
        ],
        "start": 1,
        "rows": 10000
    }
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": AUTH_TOKEN
    }

    if args.watchlist == True:
        payload["criteria"]["type"] = ["WATCHLIST"]

    response = requests.request("POST", URL, headers=headers, json=payload)

    if response.status_code == 200:
        print(f"Success {response}")
        timestamp = time.strftime("%Y%m%d-%H%M%S")  # create a timestamp for our filename
        if args.watchlist == True:
            filename = f"{args.project}_" + timestamp + "_watchlist_hits.json"
        else:
            filename = f"{args.project}_" + timestamp + "_alerts.json"
        print("Writing results to" f" {filename}")
        with open(filename, "w", encoding="utf-8") as outfile:
            json.dump(response.json(), outfile, indent=4)
    else:
        print(response)


if __name__ == "__main__":
    sys.exit(main())
