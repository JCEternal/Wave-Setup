# Wave Camera Name Change via WDM Export v1.0 3/5/25
# Created by JC
# Requires requests and panda: pip install requests panda

# Authenticates to Wave Server, pulls the device list, reads an excel file for data and matches the mac addresses to
# name the cameras per the excel sheet with a check for multi sensor channels.

# Script running video for first timers - https://youtu.be/W1CuoEo-Jtw

import requests
import pandas as pd
import os
import re
import sys

def get_confirmed_password():
    """Prompt user to enter and confirm a password."""
    while True:
        password = input("Enter Password: ")
        confirm = input("Confirm Password: ").strip()
        if password == confirm:
            return password
        print("Passwords do not match. Please try again.")

def normalize_mac(mac):
    """Convert MAC addresses to lowercase with colons for consistency."""
    return mac.lower().replace("-", ":")

# Set default paths
DEFAULT_FOLDER_PATH = "C:\\scripts"
DEFAULT_FILE_NAME = "cameras.xlsx"

# Get user input from command line or use defaults
server_ip = input("Enter Wave VMS Server IP: ")
server_port = input("Enter Wave VMS Server Port (default: 7001): ") or "7001"
server_username = input("Enter Wave VMS Username (default: admin): ") or "admin"
server_password = get_confirmed_password()

folder_path = input(f"Enter folder path (default: {DEFAULT_FOLDER_PATH}): ").strip() or DEFAULT_FOLDER_PATH
file_name = input(f"Enter Excel file name (default: {DEFAULT_FILE_NAME}): ").strip() or DEFAULT_FILE_NAME
file_path = os.path.join(folder_path, file_name)

# Ensure HTTPS is used
base_url = f"https://{server_ip}:{server_port}/rest/v3"
auth_url = f"{base_url}/login/sessions"

# Authentication
print("Authenticating with Wave VMS Server...")
auth_payload = {"username": server_username, "password": server_password}
headers = {"Content-Type": "application/json"}
requests.packages.urllib3.disable_warnings()

auth_response = requests.post(auth_url, json=auth_payload, headers=headers, verify=False)
if auth_response.status_code in [200, 201]:
    print("Authentication successful.")
    token = auth_response.json().get("token")
    headers["Authorization"] = f"Bearer {token}"
else:
    print("Authentication failed. Exiting...")
    sys.exit(1)

# Fetch device list
print("Retrieving device list from Wave...")
devices_url = f"{base_url}/devices"
devices_response = requests.get(devices_url, headers=headers, verify=False)

device_map = {}
if devices_response.status_code == 200:
    devices = devices_response.json()
    if isinstance(devices, list):
        for device in devices:
            name = device.get('name', 'Unknown')
            mac = normalize_mac(device.get('mac', 'Unknown'))
            device_id = device.get('id')
            if mac != 'unknown' and device_id:
                if mac not in device_map:
                    device_map[mac] = []
                device_map[mac].append({"id": device_id, "name": name})
    else:
        print("Unexpected response format. Exiting...")
        sys.exit(1)
else:
    print("Failed to retrieve devices. Exiting...")
    sys.exit(1)

# Read Excel file and update camera names
rename_log = []
try:
    df = pd.read_excel(file_path, usecols=["Channel", "Camera Name", "MAC Address"])
    print("Processing camera name updates...")
    for _, row in df.iterrows():
        channel = str(row['Channel']).strip()
        camera_name = str(row['Camera Name']).strip()
        mac_address = normalize_mac(str(row['MAC Address']).strip())

        if mac_address in device_map:
            for device_info in device_map[mac_address]:
                device_id = device_info["id"]
                wave_camera_name = device_info["name"]

                if channel.lower() == "single":
                    new_name = camera_name
                else:
                    match = re.search(r'channel (\d+)', wave_camera_name, re.IGNORECASE)
                    wave_channel = int(match.group(1)) if match else 1
                    ch_match = re.search(r'ch(\d+)', channel, re.IGNORECASE)
                    excel_channel = int(ch_match.group(1)) if ch_match else 1
                    if wave_channel != excel_channel:
                        continue
                    new_name = camera_name

                modify_url = f"{base_url}/devices/{device_id}"
                modify_payload = {"name": new_name}
                modify_response = requests.patch(modify_url, json=modify_payload, headers=headers, verify=False)

                if modify_response.status_code in [200, 204]:
                    print(f"Updated: {wave_camera_name} -> {new_name}")
                    rename_log.append({"Old Camera Name": wave_camera_name, "New Camera Name": new_name, "MAC Address": mac_address})
                else:
                    print(f"Failed to update {wave_camera_name}. Error: {modify_response.text}")
        else:
            print(f"MAC Address {mac_address} not found in Wave device list.")
except Exception as e:
    print(f"Error reading Excel file: {e}")
    sys.exit(1)

# Export rename log
if rename_log:
    log_df = pd.DataFrame(rename_log)
    export_path = os.path.join(folder_path, "rename_log.xlsx")
    log_df.to_excel(export_path, index=False)
    print(f"Rename log saved: {export_path}")
