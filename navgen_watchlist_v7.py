""" This script extracts MITRE TTP's from CB Enterprise EDR watchlists alerts
and generates sample MITRE ATT&CK Navigation layers.

"""
import argparse
import json
import sys
from datetime import datetime
import pandas as pd
import plotly.io as pio


def main():
    parser = argparse.ArgumentParser(prog="navgen_watchlist_v7.py", description="A program that takes WATCHLIST json file \
                                           written by get_alerts_v7.py as input and generates MITRE ATT&CK navigator layers and Pandas graphs.")
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-f", "--alert_file", required=True,
                               help="The alert data json file written by get_alerts_v7.py")
    requiredNamed.add_argument("-p", "--project", required=False,
                               help="Project Name")
    parser.add_argument("-c", "--csv", action='store_true', help="Export the enriched alert data to a csv file")
    args = parser.parse_args()

    pio.templates.default = "seaborn"
    # Load the alert data
    json_data = pd.read_json(args.alert_file)
    df_wl_hits = pd.DataFrame(json_data.results.values.tolist()).explode('report_tags')
    df_wl_hits_filtered = df_wl_hits[df_wl_hits['report_tags'].str.match('^[tT][0-9]+[\\.[0-9]*]?', na=False)]

    if args.csv == True:
        df_wl_hits_filtered.to_csv(f'{args.project}_watchlist_alerts.csv')

    pd_explode = df_wl_hits_filtered['report_tags'].str.upper()
    tl = []

    technique_enabled = True  # for future use to enable or disable a technique based on a config file
    show_sub_techniques = True  # for future use to enable or disable a technique based on a config file

    for p in pd_explode:
        # d['techniqueID'] = d.pop('technique_id')

        techniques = {
            "techniqueID": p,
            "score": 1,
            "color": "",
            "comment": "",
            "enabled": technique_enabled,
            "metadata": "",
            "showSubtechniques": show_sub_techniques
        }
        tl.append(techniques)

    VERSION = "4.1"
    NAME = "CB Enterprise EDR: Watchlist Alerts"
    DESCRIPTION = "ATT&CK Matrix Coverage for Carbon Black Cloud Enterprise EDR Watchlist hits"
    DOMAIN = "enterprise-attack"
    platform_layer = {
        "name": NAME,
        "description": DESCRIPTION,
        "domain": DOMAIN,
        "version": VERSION,
        "filters": {"platforms": ["windows", "linux", "macOS"]},
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
