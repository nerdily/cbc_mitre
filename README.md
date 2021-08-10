# cb-attack

Generate [MITRE ATT&CK®](https://attack.mitre.org/) navigation layers from [VMware Carbon Black Cloud](https://www.carbonblack.com/products/vmware-carbon-black-cloud-endpoint/) alert data.

## Overview

`cb-attack` is a collection of Python scripts that generate example MITRE ATT&CK® navigation layers based on Carbon Black Cloud alerts and events that have been tagged with ATT&CK TTP's, which can then be loaded into [ATT&CK® Navigator](https://github.com/mitre-attack/attack-navigator) for review and analysis.

This document outlines the configuration steps and procedures to generate the navigation layers for Endpoint Standard and/or Enterprise EDR alerts.

## Configuration

### Pre-requisites

- Python 3.8.5+
- Org Key (Found in the product console under **Settings** > **API Access** > **API Keys**)
JMcR
- Install packages needed for the MITRE ATT&CK Navigator
  - Node.js  (https://nodejs.org/  or https://nodejs.org/dist/v14.17.1/node-v14.17.1-x64.msi)
  - Angular CLI - 
- A running instance of the [Mitre ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator#running-the-docker-file) app.
    - Retrieve https://github.com/mitre-attack/attack-navigator/archive/refs/heads/master.zip
JMcR
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

The scripts can be run from any system running Python 3.8.5+. The following instructions show how to run the scripts from within a Python Virtual Environment and install the required Python packages.

#### **Windows**

```bash
JMcR
(Create a directory to run the tools from)
mkdir cb-attack
Copy the requisite files from the CB CSE ATT&CK folder (UCustomerSuccessEngineering/Shared%20Documents/Forms/AllItems.aspx?csf=1&web=1&e=fzub6L%2F&FolderCTID=0x012000ADBF385FB1619043817EE55303472A68&viewid=8c06708a-6d16-4b0a-b312-1c6119d48df2&id=%2Fteams%2FSBUCustomerSuccessEngineering%2FShared%20Documents%2FGeneral%2FSBU%20CSE%20Internal%2FUseful%20Scripts%20and%20Tools%2FCBC%2Fcb-attack) on sharepoint to some temp location (path-to-temp-location)
JMcR
pip3 install virtualenv
cd cb-attack
virtualenv cb-attack
cb-attack\Scripts\activate

pip3 install -r <path-to-temp-location>\requirements.txt
(This will install the packages and dependencies)
JMcR
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

To generate the navigation layers and charts `cb-attack` needs to save alert data to a json file. To save the alert data run `get_alerts.py`. `get_alerts.py` does not currently support CBC SDK and instead queries the API directly.

To view the supported parameters when using the script run `python3 get_alerts.py -h` or for Windows users `py -3 get_alerts.py -h`.

### get_alerts.py

```bash
usage: get_alerts.py [-h] -p PROJECT -e {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD} [-a {CB_ANALYTICS,WATCHLIST,ALL}] [-d DAYS] -o ORG_KEY -i API_ID -s API_SECRET

Query VMware Carbon Black Cloud for alert data.

optional arguments:
  -h, --help            show this help message and exit
  -p PROJECT, --project PROJECT
                        Project Name
  -e {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD}, --environment {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD}
                        Environment for the Base URL
  -a {CB_ANALYTICS,WATCHLIST,ALL}, --alert_type {CB_ANALYTICS,WATCHLIST,ALL}
                        The type or alert data to search for. For Endpoint Standard select CB_ANALYTICS and for Enterprise EDR select WATCHLIST.
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

`python3 get_alerts.py -p cb-attack-project -e PROD05 -a CB_ANALYTICS -d 7 -o MYORGID -s MYAPISECRET -i MYAPIID`

#### **All alerts**

This example will export CB_ANALYTICS and WATCHLIST alerts from the last 7 days.

`python3 get_alerts.py -p cb-attack-project -e PRODSYD -a ALL -d 7 -o MYORGID -s MYAPISECRET -i MYAPIID`

## Generate Charts and Navigation Layers

There are two Python scripts that generate the analytics output:

1. navgen_analytics.py
2. navgen_watchlist.py

`navgen_analytics.py` is used to create the content for the customer slide deck. `navgen_watchlist.py` is experimental at this stage.

Both scripts include contextual help and which can be accessed by using the `-h` switch. For example, `navgen_analytics.py -h` .

### **navgen_analytics.py**

`navgen_analytics.py` reads the alerts json file generated by `get_alerts.py` and creates example charts and navigation layers based on Endpoint Standard (CB_ANALYTICS) alert data.

```bash
usage: navgen_analytics.py [-h] -f ALERT_FILE [-p PROJECT]

A program that takes CB_ANALYTICS json file written by get_base_alerts.py as input and generates Mitre ATT&CK navigator layers and Pandas graphs.

optional arguments:
  -h, --help            show this help message and exit
  -f ALERT_FILE, --alert_file ALERT_FILE
                        The alert data json file written by get_alerts.py
  -p PROJECT, --project PROJECT
                        Project Name
  -c, --csv             Export enriched alert data to a csv file
```

#### **Example 1 - Charts and Navigation Layers**

This example generates ATT&CK navigation layers and charts from an alert export file called cb_analytics_alerts.json. cb_analytics_alerts.json is parsed to the program with the `-f` switch. The `-p` switch represents a project name this activity can be associated to and will be appended to the files written by `navgen_analytics.py`.

```python
python3 navgen_analytics.py -p cb_mitre_analytics -f cb_analytics_alerts.json 
```

#### **Example 2 - Export enriched alerts to CSV**



### navgen_watchlist.py

`navgen_watchlist.py` reads the alerts json file generated by `get_alerts.py` and creates a sample navigation layer based on Enterprise EDR (WATCHLIST) alert data. It currenty does not create example charts.

```bash
usage: navgen_watchlist.py [-h] -f ALERT_FILE [-p PROJECT] -e {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD} -o ORG_KEY -i API_ID -s API_SECRET

A program that takes a WATCHLIST json file written by get_base_alerts.py as input and generates a Mitre ATT&CK navigator layer

optional arguments:
  -h, --help            show this help message and exit
  -f ALERT_FILE, --alert_file ALERT_FILE
                        The alert data json file written by get_base_alerts.py
  -p PROJECT, --project PROJECT
                        Project Name
  -e {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD}, --environment {EAP1,PROD01,PROD05,PROD06,PRODNRT,PRODSYD}
                        Environment for the Base URL
  -o ORG_KEY, --org_key ORG_KEY
                        Org key (found in your product console under Settings > API Access > API Keys)
  -i API_ID, --api_id API_ID
                        API ID
  -s API_SECRET, --api_secret API_SECRET
                        API Secret Key
```

### Limitations

1. The charts, navigation layers and CSV export only include alerts that are enriched with Mitre ATT&CK TTPs. All other alerts are ommitted.
