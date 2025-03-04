import requests
import ipaddress
import time

# Function to validate IP address input (Ensures four octets)
def validate_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip.count('.') == 3  # Ensures exactly four octets
    except ValueError:
        return False

# Function to get a valid IP input from the user
def get_valid_ip(prompt):
    while True:
        ip = input(prompt)
        if validate_ip(ip):
            return ip
        print("❌ Invalid IP format. Please enter a valid IPv4 address (e.g., 192.168.1.50).")

# Function to get a confirmed password from the user
def get_confirmed_password():
    while True:
        password = input("Enter Password: ")
        confirm = input("Are you sure this password is correct? (y/n): ").strip().lower()
        if confirm == "y":
            return password
        print("🔄 Re-enter the password.")

# Get user input for Wave VMS Server
server_ip = get_valid_ip("Enter Wave VMS Server IP: ")
server_port = input("Enter Wave VMS Server Port (default: 7001): ") or "7001"
server_username = input("Enter Wave VMS Username (default: admin): ") or "admin"
server_password = get_confirmed_password()

# Get user input for camera search range with validation
camera_ip_start = get_valid_ip("Enter Camera IP Start Range (e.g., 192.168.1.50): ")
camera_ip_end = get_valid_ip("Enter Camera IP End Range (e.g., 192.168.1.100): ")

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

# Step 2: Start device search using `startIp` and `endIp`
search_url = f"{base_url}/devices/*/searches"

search_payload = {
    "port": 80,
    "credentials": {
        "user": camera_username,
        "password": camera_password
    },
    "mode": "addFoundDevices",  # ✅ Auto-add devices
    "target": {
        "startIp": camera_ip_start,
        "endIp": camera_ip_end
    }
}

search_response = requests.post(search_url, json=search_payload, headers=headers, verify=False)

if search_response.status_code == 200:
    search_result = search_response.json()
    search_id = search_result.get("id")
    print(f"✅ Device search started successfully.\nSearch ID: {search_id}")
else:
    print("❌ Failed to start device search.")
    print(f"Status Code: {search_response.status_code}")
    print(f"Response: {search_response.text}")
    exit()

# Step 3: Wait before checking status
time.sleep(10)

# Step 4: Monitor search status with animated loading
status_url = f"{base_url}/devices/*/searches/{search_id}"
loading_chars = [".", "..", "...", "...."]
loading_index = 0

while True:
    status_response = requests.get(status_url, headers=headers, verify=False)

    if status_response.status_code == 200:
        status_data = status_response.json()
        state = status_data.get("status", {}).get("state", "")

        print(f"\r🔍 Current Search State: {state}", end="", flush=True)

        if state.lower() in ["completed", "done", "finished"]:
            print("\n✅ Search completed successfully!")
            break
    else:
        print("\n❌ Failed to retrieve search status.")
        print(f"Response: {status_response.text}")
        exit()

    time.sleep(2)

# Step 5: Retrieve the list of added devices
devices_url = f"{base_url}/devices"
devices_response = requests.get(devices_url, headers=headers, verify=False)

if devices_response.status_code == 200:
    devices = devices_response.json()

    if not devices:
        print("\n⚠️ No devices found in this search range.")
    else:
        print("\n📋 List of added devices:")
        for device in devices:
            device_name = device.get("name", "Unknown")
            device_ip = device.get("url", "").replace("http://", "").split(":")[0]  # Extract IP from URL
            print(f" - {device_name} ({device_ip})")
else:
    print("\n❌ Failed to retrieve device list.")
    print(f"Response: {devices_response.text}")

# Step 6: Logout (Cleanup)
logout_url = f"{auth_url}/{token}"
requests.delete(logout_url, headers=headers, verify=False)

print("✅ Process completed successfully.")
