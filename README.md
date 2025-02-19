# Akamai SIEM Integration for Wazuh

![github_wazuh_akamai](https://github.com/user-attachments/assets/e0adcf51-4580-4a4b-8710-ea6eb60a2cc4)

This integration uses a Python script to fetch security events from the Akamai SIEM API using a time-based query. The script collects events that occurred in a 5‑minute window (from current time minus 5 minutes to current time minus 5 seconds) and outputs each event as a single JSON line for ingestion by Wazuh.

![Wazuh Discover page with Akamai events](https://github.com/user-attachments/assets/39dcef22-4a11-4357-b704-96806801c901)

## Overview

- **Purpose:**  
  Collect and decode security events from the Akamai SIEM API and deliver them to Wazuh for further analysis.

- **How It Works:**  
  Each time the script runs, it calculates a time window based on the current time:
  - **From:** Current time minus 300 seconds (5 minutes)
  - **To:** Current time  
  The script then calls the Akamai SIEM API using these parameters, decodes any URL and Base64 encoded fields in the event data, and prints each event as a JSON line.

- **Deployment:**  
  The script is executed by the Wazuh command wodle on a 5‑minute interval.

## Requirements

- **Python 3**  
- **Dependencies:**  
  Install required Python libraries using pip:
  ```bash
  pip install requests edgegrid-python
  ```
- **Akamai SIEM API Credentials:**  
  Before proceeding with the integration, it is necessary to have the API user setup correctly:
  1. On the Akamai Identity Manager, create a dedicated standard user with only the "Manage SIEM" role. 
     - You cannot create the API user using an Admin account due to Akamai restrictions on Admin users to the SIEM API. 
  2. Login to the console using the just created user, and create an API user following the SIEM API documentation: https://techdocs.akamai.com/siem-integration/reference/api-get-started
  3. After following the Akamai SIEM API documentation you should have the necessary details to fill the external configuration file values:
  - `host` – Your Akamai API host (e.g., `cloudsecurity.akamaiapis.net`)
  - `config_id` – Your security configuration ID, identifying your tenant
  - `client_token`
  - `client_secret`
  - `access_token`


## Installation

1. **Script Setup:**  
   Clone the repository in the wodle folder of your Wazuh Manager:
   ```bash
   git clone https://github.com/SyncSecurityHQ/wazuh_akamai_integration.git
   ```
   Ensure the script is executable:
   ```bash
   chmod +x /var/ossec/wodles/wazuh_akamai_integration/akamai.py
   ```

2. **Configuration File:**  
   Copy the `akamai_config.ini.template` file and name it `akamai_config.ini`.  
   Edit the `akamai_config.ini` file with your Akamai credentials. An example configuration:
   ```ini
   [default]
   host = cloudsecurity.akamaiapis.net
   config_id = YOUR_CONFIG_ID
   client_token = YOUR_CLIENT_TOKEN
   client_secret = YOUR_CLIENT_SECRET
   access_token = YOUR_ACCESS_TOKEN
   ```
   Adjust values as needed.

3. **Wazuh Command Wodle Configuration:**  
   Add this section at the end of your Wazuh Manager `ossec.conf` to run the script every 5 minutes. For example:
   ```xml
    <!-- Wazuh Akamai integration --> 
    <ossec_config>
      <wodle name="command">
        <disabled>no</disabled>
        <tag>akamai_siem</tag>
        <!-- Full path to your Python interpreter and your wodle script -->
        <command>/usr/bin/python3 /var/ossec/wodles/wazuh_akamai_integration/akamai.py</command>
        <!-- How often the script is executed (DO NOT CHANGE) -->
        <interval>5m</interval>
        <!-- Run the command immediately when the service starts -->
        <run_on_start>yes</run_on_start>
        <!-- Timeout in seconds (0 means wait indefinitely) -->
        <timeout>0</timeout>
        <!-- Do not ignore the output (so it gets ingested by Wazuh) -->
        <ignore_output>no</ignore_output>
      </wodle>
    </ossec_config>
   ```

4. **Rule custom to generate alerts:**  
  By default the events are already decoded by the native JSON decoder, but do not trigger any relevant rule.  
  From the rules tab create a new rule file named `akamai.xml` and paste the following code:
   ```xml
    <group name="akamai,">

      <rule id="100100" level="3">
        <location>command_akamai_siem</location>
        <description>Akamai - Event fetched.</description>
      </rule>

    </group>
   ```  
    Restart the Wazuh Manager service after applying the changes.
   ```bash
    systemctl restart wazuh-manager
   ```  

## How the Script Works

- **Time Window Calculation:**  
  The script calculates the current Unix epoch time and sets:
  - `from_time = now - 300` (5 minutes ago)
  - `to_time = now` (current time)

- **API Request:**  
  It sends a GET request to:
  ```
  https://{host}/siem/v1/configs/{config_id}
  ```
  with query parameters:
  - `from`
  - `to`
  - `limit` (set at the maximum available value per query which is 600K as of 18/02/2025)

- **Event Decoding:**  
  The script decodes URL-encoded and Base64-encoded fields in the `attackData` and URL-decodes fields in the `httpMessage` section.

- **Output:**  
  Each decoded event is printed as a JSON string (one event per line), which Wazuh ingests.

## Usage

- **Manual Testing:**  
  You can run the script manually to test that it outputs valid JSON:
  ```bash
  /usr/bin/python3 /var/ossec/wodles/wazuh_akamai_integration/akamai.py
  ```
- **Wazuh Integration:**  
  With the above wodle configuration, Wazuh will execute the script every 5 minutes, ingesting any events output by the script.

## Troubleshooting

- **No Events Found:**  
  If no events are returned, check the time window and verify that the API is receiving data for the specified period.

- **Decoding Errors:**  
  Ensure that all necessary fields are correctly URL and Base64 encoded on the Akamai side. Review the log output (the script logs to stderr) for error messages.

- **API Connectivity:**  
  Verify that your credentials and host settings in `akamai_config.ini` are correct and that your network allows outbound HTTPS connections to the Akamai API host.
