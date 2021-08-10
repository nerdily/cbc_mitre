# !/usr/bin/env python3

""" This script extracts Mitre TTP's from CB EEDR Watchlists alerts to a
Mitre ATT&CK Navigation layer.

"""

# TODO: Refactor codebase from Jupyter Notebook export
# PEP8 Compliance
# Support CBC SDK
# add argparse CLI


import argparse
import json
import requests
import sys
from datetime import datetime

import pandas as pd
import plotly.io as pio


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

    return f"{environment}/threathunter/watchlistmgr/v3/orgs/{org_key}/reports/"


def main():
    
    parser = argparse.ArgumentParser(prog="navgen_watchlist.py",
                                     description="A program that takes a \
                                         WATCHLIST json file written by \
                                         get_base_alerts.py as input and \
                                         generates a Mitre ATT&CK navigator layer")
    parser.add_argument("-f", "--alert_file", required=True,
                        help="The alert data json file written by \
                              get_base_alerts.py")
    parser.add_argument("-p", "--project", required=False,
                        help="Project Name")
    parser.add_argument("-e", "--environment", required=True, default="PROD05",
                        choices=["EAP1", "PROD01", "PROD05",
                                 "PROD06", "PRODNRT", "PRODSYD"],
                        help="Environment for the Base URL")
    parser.add_argument("-o", "--org_key", required=True,
                        help="Org key (found in your product console under \
                              Settings > API Access > API Keys)")
    parser.add_argument("-i", "--api_id", required=True,
                        help="API ID")
    parser.add_argument("-s", "--api_secret", required=True,
                        help="API Secret Key")
    parser.add_argument("-c", "--csv", action='store_false',
                        help="Export the enriched alert data to a csv file")

    args = parser.parse_args()
    
    URL = build_base_url(args.environment, args.org_key)
    AUTH_TOKEN = f"{args.api_secret}/{args.api_id}"

    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    pd.set_option('display.max_colwidth', None)
    pio.templates.default = "seaborn"

    json_data = pd.read_json(args.alert_file)

    bn = json_data.results.values.tolist()
    df_alert = pd.DataFrame(json_data.results.values.tolist())
    df_alert = df_alert.sort_index(axis=1)
    df_alert.head(50)

    s_report_id = df_alert['report_id'].drop_duplicates().reset_index(drop=True)

    payload = {}

    headers = {
        'Content-Type': 'application/json',
        'X-Auth-Token': AUTH_TOKEN
    }

    appended_data = []
    for report in s_report_id:
        try:
            report_url = f"{build_base_url(args.environment, args.org_key)}{report}"
            report_details = requests.get(report_url,
                                headers=headers, data=payload).text
            d = json.loads(report_details)
            appended_data.append(d)
        except:
            print("ERROR: " + report)

    pdr = pd.json_normalize(appended_data).add_prefix('report_')

    mitre_merge_alert_ttp2 = pd.merge(
        df_alert,
        pdr,
        on=["report_id"]
    )
    
    if args.csv == True:
        mitre_merge_alert_ttp2.to_csv(f'{args.project}_watchlist_alerts.csv')

    pdr['ex_tags'] = pdr['report_tags']
    pdr.explode('ex_tags').head(5)

    pd_explode = pdr.explode('report_tags')
    pd_explode = pd_explode['report_tags'].str.extract(r'(t[0-9]{4}|T[0-9]{4})').dropna(thresh=1).drop_duplicates().reset_index(drop=True)
    pd_explode = pd_explode[0].str.upper()
    tl = []

    technique_enabled = True #for future use to enable or disable a technique based on a config file
    show_tub_techniques = False #for future use to enable or disable a technique based on a config file

    for p in pd_explode:
        #d['techniqueID'] = d.pop('technique_id')
        
        techniques = {
                "techniqueID": p,
                "score": 1,
                "color": "",
                "comment": "",
                "enabled": technique_enabled,
                "metadata": "",
                "showSubtechniques": show_tub_techniques
            }
        tl.append(techniques)

    VERSION = "4.1"
    NAME = "CB Enterprise EDR: Watchlist Alerts"
    DESCRIPTION = "ATT&CK Matrix Coverage for Carbon Black Cloud EEDR Alerts"
    DOMAIN = "enterprise-attack"
    platform_layer = {
        "name": NAME,
        "description": DESCRIPTION,
        "domain": DOMAIN,
        "version": VERSION,
        "filters": {"platforms": ["windows","linux","macOS"]},
        "techniques": tl,
        "gradient": {
            "colors": ["#ffffff", "#7F35B2"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1d428a"
    }
    
    filetimestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    with open(f'{filetimestamp}_{args.project}_attack_cb_eedr.json', 'w', encoding='utf-8') as outfile:
        json.dump(platform_layer, outfile, indent=4, ensure_ascii=False)
        
if __name__ == "__main__":
    sys.exit(main())
