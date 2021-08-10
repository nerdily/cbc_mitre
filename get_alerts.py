# !/usr/bin/env python3

"""Retrieve CB Analytics and Watchlist alert data and save to a json file.
"""

import argparse
import json
import requests
import sys


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


def build_base_url(environment, org_key):
    """Build the base URL

    rtype: string
    """

    environment = get_environment(environment)

    return f"{environment}/appservices/v6/orgs/{org_key}/alerts/_search"


def main():
    """Function to parse arguments and retrieve the alert restuls"""

    parser = argparse.ArgumentParser(prog="get_alerts.py",
                                     description="Query VMware Carbon Black \
                                         Cloud for alert data.")
    parser.add_argument("-p", "--project", required=True,
                        help="Project Name")
    parser.add_argument("-e", "--environment", required=True, default="PROD05",
                        choices=["EAP1", "PROD01", "PROD02", "PROD05",
                                 "PROD06", "PRODNRT", "PRODSYD"],
                        help="Environment for the Base URL")
    parser.add_argument("-a", "--alert_type", default="CB_ANALYTICS",
                        choices=["CB_ANALYTICS", "WATCHLIST"],
                        help="The type or alert data to search for. \
                              For Endpoint Standard select CB_ANALYTICS \
                                  and for Enterprise EDR select WATCHLIST.")
    parser.add_argument("-d", "--days", default=7,
                        help="Time range in days to query.")
    parser.add_argument("-o", "--org_key", required=True,
                        help="Org key (found in your product console under \
                              Settings > API Access > API Keys)")
    parser.add_argument("-i", "--api_id", required=True,
                        help="API ID")
    parser.add_argument("-s", "--api_secret", required=True,
                        help="API Secret Key")
    args = parser.parse_args()

    URL = build_base_url(args.environment, args.org_key)
    AUTH_TOKEN = f"{args.api_secret}/{args.api_id}"

    if args.alert_type == "CB_ANALYTICS":
        alert_type = ["CB_ANALYTICS"]
    elif args.alert_type == "WATCHLIST":
        alert_type = ["WATCHLIST"]

    payload = {
        "criteria":
            {
                "group_results": "true",
                "minimum_severity": 1,
                "type": alert_type,
                "create_time": {
                    "range": f"-{args.days}d"
                    }
            },
        "sort": [{
            "field": "first_event_time",
            "order": "DESC"
        }],
        "rows": 9999,
        "start": 0
    }
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": AUTH_TOKEN
    }

    response = requests.request("POST", URL, headers=headers, json=payload)

    if response.status_code == 200:
        print(f"Success {response}")
        filename = f"{args.project}_{args.alert_type.lower()}_alert.json"
        print("Writing results to" f" {filename}")
        with open(filename, "w", encoding="utf-8") as outfile:
            json.dump(response.json(), outfile, indent=4)
    else:
        print(response)


if __name__ == "__main__":
    sys.exit(main())
