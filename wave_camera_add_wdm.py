# Wave Camera Add via WDM Export v1.0 3/5/25
# Created by JC
# Requires requests and panda: pip install requests panda

# Authenticates to Wave Server, reads the excel file export for camera IP addresses, ignores multi duplicates and adds
# all cameras using the addFoundDevices mode of Start Device Search

# Script running video for first timers - https://youtu.be/W1CuoEo-Jtw

import requests
import ipaddress
import time
import pandas as pd


# Function to get a confirmed password from the user
def get_confirmed_password():
    while True:
        password = input("Enter Password: ")
        confirm = input("Are you sure this password is correct? (y/n): ").strip().lower()
        if confirm == "y":
            return password
        print("🔄 Re-enter the password.")


# Read camera data from Excel file
def read_camera_data_from_excel(filename):
    try:
        df = pd.read_excel(filename)
        if "IP Address" not in df.columns:
            print("❌ Error: Missing 'IP Address' column in the Excel file.")
            exit()

        unique_ips = set()

        for _, row in df.iterrows():
            ip = str(row["IP Address"]).strip()
            if validate_ip(ip):
                unique_ips.add(ip)  # Store unique IPs for adding cameras

        if not unique_ips:
            print("❌ No valid IP addresses found in the file.")
            exit()

        return list(unique_ips)
    except Exception as e:
        print(f"❌ Error reading Excel file: {e}")
        exit()


# Function to validate IP address input
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# Get user input for Wave VMS Server
server_ip = input("Enter Wave VMS Server IP: ")
server_port = input("Enter Wave VMS Server Port (default: 7001): ") or "7001"
server_username = input("Enter Wave VMS Username (default: admin): ") or "admin"
server_password = get_confirmed_password()

# Get the Excel file containing IP addresses
excel_filename = input("Enter the Excel file name (e.g., devices.xlsx): ")
unique_ips = read_camera_data_from_excel(excel_filename)

camera_username = input("Enter Camera Username (default: admin): ") or "admin"
camera_password = get_confirmed_password()

# Ensure HTTPS is used
base_url = f"https://{server_ip}:{server_port}/rest/v3"
auth_url = f"{base_url}/login/sessions"

# Step 1: Authenticate and obtain session token
auth_payload = {
    "username": server_username,
    "password": server_password
}
headers = {"Content-Type": "application/json"}

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings()

auth_response = requests.post(auth_url, json=auth_payload, headers=headers, verify=False)

if auth_response.status_code in [200, 201]:
    token = auth_response.json().get("token")
    headers["Authorization"] = f"Bearer {token}"
else:
    print("❌ Authentication failed. Check credentials.")
    print(f"Response: {auth_response.text}")
    exit()

# Step 2: Search & Add all devices by IP address
for ip in unique_ips:
    print(f"\n🔍 Searching and adding device at: {ip}")

    search_url = f"{base_url}/devices/*/searches"

    search_payload = {
        "port": 80,
        "credentials": {
            "user": camera_username,
            "password": camera_password
        },
        "mode": "addFoundDevices",
        "target": {
            "ip": ip
        }
    }

    search_response = requests.post(search_url, json=search_payload, headers=headers, verify=False)

    if search_response.status_code == 200:
        search_result = search_response.json()
        search_id = search_result.get("id")
        print(f"✅ Search started successfully for {ip}. Search ID: {search_id}")
    else:
        print(f"❌ Failed to start device search for {ip}.")
        print(f"Status Code: {search_response.status_code}")
        print(f"Response: {search_response.text}")
        continue  # Move to the next IP if this one fails

    time.sleep(5)  # Wait before checking status

# Step 3: Logout (Cleanup)
logout_url = f"{auth_url}/{token}"
requests.delete(logout_url, headers=headers, verify=False)

print("✅ Process completed successfully.")
