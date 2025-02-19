#!/usr/bin/env python3
"""
Akamai SIEM Wazuh Wodle using time-based mode with EdgeGrid Authentication

This script polls the Akamai SIEM API for events that occurred in a defined time window.
It calculates the current time, subtracts 5 minutes for the start of the window, and sets
the end of the window to current time minus 5 seconds (to account for API latency).
The events are then decoded and printed as one JSON per line for ingestion by Wazuh.

Dependencies:
    pip install requests edgegrid-python
"""

import time
import requests
import json
import logging
import urllib.parse
import base64
import configparser
import sys

from akamai.edgegrid import EdgeGridAuth

# -------------------------------
# Load configuration from external file
# -------------------------------
CONFIG_FILE = "/var/ossec/wodles/wazuh_akamai_integration/akamai_config.ini"
config = configparser.ConfigParser()
try:
    config.read(CONFIG_FILE)
    cfg = config["default"]
except Exception as e:
    logging.error("Error reading configuration file %s: %s", CONFIG_FILE, e)
    sys.exit(1)

HOST = cfg.get("host")
CONFIG_ID = cfg.get("config_id")
CLIENT_TOKEN = cfg.get("client_token")
CLIENT_SECRET = cfg.get("client_secret")
ACCESS_TOKEN = cfg.get("access_token")
LIMIT = 600000

# -------------------------------
# Set up logging (directed to a file or stderr as needed)
# -------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# -------------------------------
# Create a requests session with EdgeGrid authentication.
# -------------------------------
session = requests.Session()
session.auth = EdgeGridAuth(
    client_token=CLIENT_TOKEN,
    client_secret=CLIENT_SECRET,
    access_token=ACCESS_TOKEN
)

# -------------------------------
# Helper functions for decoding event fields
# -------------------------------
def decode_b64_field(value):
    try:
        decoded_url = urllib.parse.unquote(value)
        if decoded_url.endswith(";"):
            decoded_url = decoded_url[:-1]
        decoded_bytes = base64.b64decode(decoded_url)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        logging.error("Error base64 decoding value '%s': %s", value, e)
        return value

def decode_event_fields(event):
    attack_keys = ["rules", "ruleVersions", "ruleMessages", "ruleTags", "ruleData", "ruleSelectors", "ruleActions"]
    attack_data = event.get("attackData")
    if isinstance(attack_data, dict):
        for key in attack_keys:
            if key in attack_data and isinstance(attack_data[key], str):
                attack_data[key] = decode_b64_field(attack_data[key])
    http_msg = event.get("httpMessage")
    if isinstance(http_msg, dict):
        for key, value in http_msg.items():
            if isinstance(value, str):
                try:
                    http_msg[key] = urllib.parse.unquote(value)
                except Exception as e:
                    logging.error("Error URL decoding httpMessage field '%s': %s", key, e)
    return event

# -------------------------------
# Fetch events using time-based mode
# -------------------------------
def fetch_events_time_based(from_epoch, to_epoch):
    url = f"https://{HOST}/siem/v1/configs/{CONFIG_ID}"
    params = {
        "from": from_epoch,
        "to": to_epoch,
        "limit": LIMIT
    }
    try:
        response = session.get(url, params=params, timeout=30)
        response.raise_for_status()
        lines = [line for line in response.text.splitlines() if line.strip()]
        events = []
        # Iterate through each line, skipping metadata if present
        for obj in lines:
            parsed = json.loads(obj)
            if "total" in parsed or "offset" in parsed:
                continue
            else:
                events.append(parsed)
        return events
    except Exception as e:
        logging.error("Error fetching events from %s: %s", url, e)
        return None

def process_events(events):
    for event in events:
        decoded_event = decode_event_fields(event)
        print(json.dumps(decoded_event))
        sys.stdout.flush()

# -------------------------------
# Main execution: fetch events from (now - 5min) to (now - 5sec)
# -------------------------------
def main():
    now = int(time.time())
    from_time = now - 300   # 5 minutes ago (300 seconds)
    to_time = now           # current time
    logging.info("Fetching events from %s to %s", from_time, to_time)
    
    events = fetch_events_time_based(from_time, to_time)
    if events:
        process_events(events)
    else:
        logging.info("No new events found.")

if __name__ == "__main__":
    main()
