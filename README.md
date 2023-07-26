# cb-attack

Generate [MITRE ATT&CK®](https://attack.mitre.org/) navigation layers from [VMware Carbon Black Cloud](https://www.carbonblack.com/products/vmware-carbon-black-cloud-endpoint/) alert data.

## Overview

`cb-attack` is a collection of Python scripts that generate example MITRE ATT&CK® navigation layers based on Carbon Black Cloud alerts and events that have been tagged with ATT&CK TTP's, which can then be loaded into [ATT&CK® Navigator](https://github.com/mitre-attack/attack-navigator) for review and analysis.

This document outlines the configuration steps and procedures to generate the navigation layers for Endpoint Standard and/or Enterprise EDR alerts.

## Configuration

### Pre-requisites

- Python 3.8.5+
- Org Key (Found in the product console under **Settings** > **API Access** > **API Keys**)
- Access to the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). This is where you'll take your final output and load it to view. 

### API Access

`cb-attack` requires a single read-only API key.

#### **Create a read-only API Access Level**

   1. From **Settings** > **API Access**, select the **Access Levels** tab.
   2. Click the **Add Access Level** button and apply the following settings:
      - Name: `READ_ONLY_CB_MITRE`
      - Description: Custom Read-only Access Level to retrieve CB Analytics and Watchlist alert data
      - Alerts > General Information > Org.alerts: `Read`
      - Custom Detections > Watchlists > Org.watchlists: `Read`
      - Custom Detections > Feeds> Org.feeds: `Read`
      - Device > General Information > Device: `Read`
      - Search > Events > org.search.events: `Read`
      - Click **Save**

#### **Create a read-only API Key**

   1. From **Settings** > **API Access**, select the **API Keys** tab.
   2. Click the **Add API** Key button and apply the following settings:
      - Name: `READ_ONLY_CB_ALERT_DATA`
      - Description: Read-only API Key to retrieve CB Analytics and Watchlist Alert data.
      - Access Level type: `Custom`
      - Custom Access Level: `READ_ONLY_CB_MITRE`
      - Click **Save**

#### **API Requirements Table**

| Endpoint Standard | EEDR | CATEGORY          | PERMISSION NAME     | .NOTATION NAME    | PERMISSION |
|-------------------|------|-------------------|---------------------|-------------------|------------|
|         X         | X    | Alerts            | General information | org.alerts        | Read       |
|                   | X    | Custom Detections | Watchlists          | org.watchlists    | Read       |
|                   | X    | Custom Detections | Feeds               | org.feeds         | Read       |
|         X         | X    | Device            | General information | device            | Read       |
|         X         | X    | Search            | Events              | org.search.events | Read       |

<br/>

### Configure a Python Virtual Environment

The scripts can be run from any system running Python 3.8.5+. The following instructions show how to run the scripts from within a Python Virtual Environment and install the required Python packages. Many IDEs such as [PyCharm](https://www.jetbrains.com/pycharm/) will build the environment for you based on the included requirements.txt file in this repo.

#### **Windows**

```bash
(Create a directory to run the tools from)
mkdir cb-attack
pip3 install virtualenv
cd cb-attack
virtualenv cb-attack
cb-attack\Scripts\activate

pip3 install -r <path-to-temp-location>\requirements.txt
```

#### **Linux/MacOS**

```bash
pip3 install virtualenv
mkdir cb-attack
cd cb-attack
virtualenv .
source bin/activate
pip3 install -r /path/to/requirements.txt
```

## Download Alert Data

To generate the navigation layers and charts `cb-attack` needs to save alert data to a json file. To save the alert data run `get_alerts.py`. `get_alerts.py` does not use the CBC SDK and instead queries the API directly.

To view the supported parameters when using the script run `python3 get_alerts.py -h` or for Windows users `py -3 get_alerts.py -h`.

### get_alerts_v7.py

```bash
usage: get_alerts_vy.py [-h] -p PROJECT -e {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD} [-a {CB_ANALYTICS,WATCHLIST,ALL}] [-d DAYS] -o ORG_KEY -i API_ID -s API_SECRET

Query VMware Carbon Black Cloud for v7 alert data.

optional arguments:
  -h, --help            show this help message and exit
  -p PROJECT, --project PROJECT
                        Project Name
  -e {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD}, --environment {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD}
                        Environment for the Base URL
  -d DAYS, --days DAYS  Time range in days to query.
  -o ORG_KEY, --org_key ORG_KEY
                        Org key (found in your product console under Settings > API Access > API Keys)
  -i API_ID, --api_id API_ID
                        API ID
  -s API_SECRET, --api_secret API_SECRET
                        API Secret Key
```

### Examples

#### **Endpoint Standard alerts only**

This example will export Endpoint Standard alerts from the last 7 days.

`python3 get_alerts.py -p cb-attack-project -e PROD05 -d 7 -o MYORGID -s MYAPISECRET -i MYAPIID`

#### **All alerts**

This example will export CB_ANALYTICS and WATCHLIST alerts from the last 7 days.

`python3 get_alerts.py -p cb-attack-project -e PRODSYD -a ALL -d 7 -o MYORGID -s MYAPISECRET -i MYAPIID`

## Generate Charts and Navigation Layers

The script that generates the analytics output is called navgen_analytics_v7.py

`navgen_analytics_v7.py` is used to create the content for the customer slide deck.

The script includes contextual help and which can be accessed by using the `-h` switch. For example, `navgen_analytics.py -h` .

### **navgen_analytics_v7.py**

`navgen_analytics_vy.py` reads the alerts json file generated by `get_alerts.py` and creates example charts and navigation layers based on Endpoint Standard (CB_ANALYTICS) alert data.

```bash
usage: navgen_analytics.py [-h] -f ALERT_FILE [-p PROJECT]

A program that takes CB_ANALYTICS json file written by get_base_alerts.py as input and generates Mitre ATT&CK navigator layers and Pandas graphs.

optional arguments:
  -h, --help            show this help message and exit
  -f ALERT_FILE, --alert_file ALERT_FILE
                        The alert data json file written by get_alerts.py
  -p PROJECT, --project PROJECT
                        Project Name
  -c, --csv             Export enriched alert data to a csv file (optional)
```

#### **Example 1 - Charts and Navigation Layers**

This example generates ATT&CK navigation layers and charts from an alert export file called cb_analytics_alerts.json. cb_analytics_alerts.json is parsed to the program with the `-f` switch. The `-p` switch represents a project name this activity can be associated to and will be appended to the files written by `navgen_analytics.py`.

```python
python3 navgen_analytics_v7.py -p cb_mitre_analytics -f cb_analytics_alerts.json 
```


### Limitations

1. The charts, navigation layers and CSV export only include alerts that are enriched with Mitre ATT&CK TTPs. All other alerts are ommitted as they are proprietary to Carbon Black Cloud.
