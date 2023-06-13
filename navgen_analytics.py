# !/usr/bin/env python3

"""This script extracts Mitre ATT&CK TTPs from CB Endpoint Standard alert data
and generates sample Mitre ATT&CK Navigation layers

TODO:
"""

import argparse
import json
import sys
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.io as pio

from attackcti import attack_client


def main():

    parser = argparse.ArgumentParser(prog="navgen_analytics.py",
                                     description="A program that takes \
                                         CB_ANALYTICS json file written by \
                                         get_base_alerts.py as input and \
                                         generates Mitre ATT&CK navigator layers\
                                         and Pandas graphs.")
    parser.add_argument("-f", "--alert_file", required=True,
                        help="The alert data json file written by \
                              get_base_alerts.py")
    parser.add_argument("-p", "--project", required=False,
                        help="Project Name")
    parser.add_argument("-c", "--csv", action='store_true',
                        help="Export the enriched alert data to a csv file")

    args = parser.parse_args()

    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    pd.set_option('display.max_colwidth', None)
    pio.templates.default = "seaborn"

    json_data = pd.read_json(args.alert_file)
    bn = json_data.results.values.tolist()
    df_alert = pd.DataFrame(json_data.results.values.tolist())
    df_alert = df_alert.loc[df_alert['type'] == 'CB_ANALYTICS']
 
    df_column_headers = df_alert.columns.tolist()

    df_threat_indicators = pd.json_normalize(bn, 'threat_indicators', df_column_headers, record_prefix='threat_indicators_', errors='ignore')
    df_ttps = df_threat_indicators.explode('threat_indicators_ttps').drop(columns=['threat_indicators']).reset_index()
    df_ttps['mitre_technique'] = df_ttps['threat_indicators_ttps'].str.extract(r'(?<=MITRE_)(.*?)(?=\_)')
    df_ttps.head()
    
    lift = attack_client()
    all_techniques = lift.get_techniques()
    all_techniques = lift.remove_revoked_deprecated(all_techniques)
    len(all_techniques)

    all_techniques = lift.get_techniques(stix_format=False)
    all_techniques = lift.remove_revoked_deprecated(all_techniques)

    # Get all Mitre Techniques
    techniques_df = pd.json_normalize(all_techniques)
    # Drop sub-techniques
    techniques_df = techniques_df[techniques_df['is_subtechnique']==False]
    techniques_df = techniques_df[['matrix','tactic','technique','technique_id']]

    # technique_id has a one to many relationship with tactic and the tactic column stores values as a list. This command explodes (flattens) the tactic values so that we are left with a table of all techniques and tactics.
    techniques_df = techniques_df.explode("tactic")

    mitre_merge_alert_ttp = pd.merge(
        df_ttps,
        techniques_df,
        left_on=["mitre_technique"],
        right_on=["technique_id"],
    )
    
    if args.csv == True:
        mitre_merge_alert_ttp.to_csv(f'{args.project}_alerts.csv')

    mitre_merge_alert_ttp.sort_values(by='severity', ascending=False).reset_index(drop=True).head()
    
    mitre_merge_alert_ttp.loc[mitre_merge_alert_ttp['severity'] >= 8].sort_values(by='severity', ascending=False).reset_index(drop=True).head()

    mitre_merge_alert_ttp.loc[mitre_merge_alert_ttp['technique'] == "Account Manipulation"].sort_values(by='severity', ascending=False).reset_index(drop=True).head()

    df_bar = (mitre_merge_alert_ttp['severity']
            .value_counts()
            .rename_axis('severity')
            .reset_index(name='count')
            .sort_values(by=['severity']))
    fig = px.bar(df_bar, x='severity', y='count',
                title="CB Analytics Alerts by Severity",
                labels={"severity": "Severity",
                        "count": "Count"})
    
    fig.write_image(f"{args.project}_bar_cb_analytics_by_severity.png", engine="kaleido")

    df_bar = (mitre_merge_alert_ttp['tactic']
            .value_counts()
            .rename_axis('tactic')
            .reset_index(name='count')
            .sort_values(by=['count'], ascending=True))
    fig = px.bar(df_bar, y='count', x='tactic',
                height=600,
                title="CB Analytics Alerts by MITRE ATT&CK Tactic",
                labels={"tactic": "MITRE ATT&CK Tactic",
                        "count": "Count"})
    
    fig.write_image(f"{args.project}_bar_cb_analytics_by_tactic.png", engine="kaleido")

    df_bar = (mitre_merge_alert_ttp['technique']
            .value_counts()
            .rename_axis('technique')
            .reset_index(name='count')
            .sort_values(by=['count'], ascending=True))
    fig = px.bar(df_bar, x='count', y='technique', orientation='h',
                height=600,
                title="CB Analytics Alerts by MITRE ATT&CK Technique",
                labels={"technique": "MITRE ATT&CK Technique",
                        "count": "Count"})
    
    fig.write_image(f"{args.project}_bar_cb_analytics_by_technique.png", engine="kaleido")

    df_tactic = (mitre_merge_alert_ttp['tactic']
            .value_counts()
            .rename_axis('tactic')
            .reset_index(name='count')
            .sort_values(by=['count'], ascending=True)).set_index('tactic')
    tactic_count = df_tactic['count'].tolist()
    tactic = df_tactic.index.values.tolist()

    fig = px.line_polar(df_tactic, 
                        r=tactic_count, 
                        theta=tactic,
                        line_close=True, 
                        title="CB Analytics Alerts by MITRE ATT&CK Tactic")
    fig.update_traces(fill='toself')
    fig.update_layout(
    polar=dict(
        radialaxis=dict(
        visible=True
        ),
    ),
    showlegend=False
    )
    
    fig.write_image(f"{args.project}_radar_cb_analytics_by_tactic.png", engine="kaleido")

    columns = [
        "id",
        "legacy_alert_id",
        "process_name",
        "threat_indicators_sha256",
        "severity",
        "reason",
        "tactic",
        "technique",
        "technique_id",
        "device_name",
        "device_username",
        "sensor_action"
    ]

    df = mitre_merge_alert_ttp[columns].rename_axis(None).reset_index(drop=True)
    data = df[["tactic","technique_id"]].reset_index(drop=True).drop_duplicates()
    data = data.to_dict('records')

    tl = []

    technique_enabled = True  # for future use to enable or disable a technique based on a config file
    show_tub_techniques = False  # for future use to enable or disable a technique based on a config file

    for d in data:

        techniques = {
                "techniqueID": d.get('technique_id'),
                "tactic": d.get('tactic'),
                "score": 1,
                "color": "",
                "comment": "",
                "enabled": technique_enabled,
                "metadata": "",
                "showSubtechniques": show_tub_techniques
            }
        tl.append(techniques)

    VERSION = "4.2"
    NAME = "Carbon Black ATT&CK Analytics: Basic Example"
    DESCRIPTION = "CB Analytics/Endpoint Standard"
    DOMAIN = "enterprise-attack"
    platform_layer = {
        "name": NAME,
        "description": DESCRIPTION,
        "domain": DOMAIN,
        "version": VERSION,
        "filters": {"platforms": ["windows", "linux", "macOS"]},
        "sorting": 3,
        "techniques": tl,
        "gradient": {
            "colors": ["#ffffff", "#78BE20"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1d428a"
    }

    filetimestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    with open(f'{filetimestamp}_{args.project}_attack_cb_basic.json', 'w', encoding='utf-8') as outfile:
        json.dump(platform_layer, outfile, indent=4, ensure_ascii=False)

    data = df[["tactic","technique_id","device_name"]].reset_index(drop=True).drop_duplicates()
    grouped = data.groupby(['tactic','technique_id'], as_index=False).agg({'device_name': lambda x: x.tolist()})
    grouped = grouped.to_dict(orient="records")

    tl = []

    technique_enabled = True #for future use to enable or disable a technique based on a config file
    show_tub_techniques = False #for future use to enable or disable a technique based on a config file

    for d in grouped:
        #d['techniqueID'] = d.pop('technique_id')
        
        techniques = {
                "techniqueID": d.get('technique_id'),
                "tactic": d.get('tactic'),
                "score": 1,
                "color": "",
                "comment": "",
                "enabled": technique_enabled,
                "metadata": [
                    {
                        "name": "Device(s)",
                        "value": ', '.join(d.get('device_name'))
                    }
                ],
                "showSubtechniques": show_tub_techniques
            }
        tl.append(techniques)

    VERSION = "4.2"
    NAME = "Carbon Black ATT&CK Analytics: Metadata Example"
    DESCRIPTION = "CB Analytics/Endpoint Standard"
    DOMAIN = "enterprise-attack"
    platform_layer = {
        "name": NAME,
        "description": DESCRIPTION,
        "domain": DOMAIN,
        "version": VERSION,
        "filters": {"platforms": ["windows","linux","macOS"]},
        "sorting": 3,    
        "techniques": tl,
        "gradient": {
            "colors": ["#ffffff", "#00C1D5"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1d428a"
    }

    filetimestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    with open(f'{filetimestamp}_{args.project}_attack_cb_metadata_devices.json', 'w', encoding='utf-8') as outfile:
        json.dump(platform_layer, outfile, indent=4, ensure_ascii=False)

    df_score = (df['technique_id']
            .value_counts()
            .rename_axis('technique_id')
            .reset_index(name='count')
            .sort_values(by=['count'], ascending=True))

    tl = []

    technique_enabled = True #for future use to enable or disable a technique based on a config file
    show_tub_techniques = False #for future use to enable or disable a technique based on a config file
    max_score = df_score['count'].max().item() # Ensure the gradient is set correctly and return int

    for index, row in df_score.iterrows():
        #d['techniqueID'] = d.pop('technique_id')
        
        techniques = {
                "techniqueID": row['technique_id'],
                "score": row['count'],
                "color": "",
                "comment": "",
                "enabled": technique_enabled,
                "metadata": [],
                "showSubtechniques": show_tub_techniques
            }
        tl.append(techniques)

    VERSION = "4.2"
    NAME = "CB Endpoint Standard: Analytic Alerts with Scoring"
    DESCRIPTION = "CB Analytics/Endpoint Standard"
    DOMAIN = "enterprise-attack"
    platform_layer = {
        "name": NAME,
        "description": DESCRIPTION,
        "domain": DOMAIN,
        "version": VERSION,
        "filters": {"platforms": ["windows","linux","macOS"]},
        "sorting": 3,    
        "techniques": tl,
        "gradient": {
            "colors": ["#ffffff", "#0091da"],
            "minValue": 0,
            "maxValue": max_score
        },
        "legendItems": [
            {
                "color": "#ffffff",
                "label": "No alerts or events"
            },
            {
                "color": "#0091da",
                "label": "TTP identified"
            }
        ],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1d428a"
    }

    filetimestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    with open(f'{filetimestamp}_{args.project}_attack_cb_metadata_score.json', 'w', encoding='utf-8') as outfile:
        json.dump(platform_layer, outfile, indent=4, ensure_ascii=False)

    data = df[["technique_id","device_name","id"]].reset_index(drop=True).drop_duplicates()
    grouped = data.groupby(['technique_id'], as_index=False).agg({'id': lambda x: x.tolist()})

    score = []

    for index, row in grouped.iterrows():
        score.append(len(row['id']))
        
    grouped = grouped.assign(score = score)

    grouped['id'] = [',\n\n'.join(map(str, x)) for x in grouped['id']]

    tl = []

    technique_enabled = True #for future use to enable or disable a technique based on a config file
    show_tub_techniques = False #for future use to enable or disable a technique based on a config file
    max_score = df_score['count'].max().item() # Ensure the gradient is set correctly and return int

    for index, row in grouped.iterrows():
        #d['techniqueID'] = d.pop('technique_id')
        
        techniques = {
                "techniqueID": row['technique_id'],
                "score": row['score'],
                "color": "",
                "comment": "",
                "enabled": technique_enabled,
                "metadata": [
                    {
                        "name": "Alert ID",
                        "value": row['id']
                    }
                ],
                "showSubtechniques": show_tub_techniques
            }
        tl.append(techniques)

    VERSION = "4.2"
    NAME = "CB Endpoint Standard: Analytic Alerts with scoring by alert count"
    DESCRIPTION = "CB Analytics/Endpoint Standard"
    DOMAIN = "enterprise-attack"
    platform_layer = {
        "name": NAME,
        "description": DESCRIPTION,
        "domain": DOMAIN,
        "version": VERSION,
        "filters": {"platforms": ["windows","linux","macOS"]},
        "sorting": 3,
        "techniques": tl,
        "gradient": {
            "colors": ["#ffffff", "#7932A9"],
            "minValue": 0,
            "maxValue": max_score
        },
        "legendItems": [
            {
                "color": "#ffffff",
                "label": "No alerts or events"
            },
            {
                "color": "#0091da",
                "label": "TTP identified"
            }
        ],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1d428a"
    }

    filetimestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    with open(f'{filetimestamp}_{args.project}_attack_cb_metadata_score_alert_count.json', 'w', encoding='utf-8') as outfile:
        json.dump(platform_layer, outfile, indent=4, ensure_ascii=False)
        
        
if __name__ == "__main__":
    sys.exit(main())
