# Created by JC with the help of GTP4o
# February 28, 2025
# !You will need Requests installed
# install requests with pip install requests

#! python
import requests
import json
import sys

# Disable SSL warnings (if using self-signed certificates)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


# Function to prompt for server details and credentials
def get_server_details():
    print("Enter Wisenet Wave VMS server details:")
    server_ip = input("Server IP Address: ").strip()

    # Prompt for port with default option
    port = input("Port (default 7001, hit enter to use default): ").strip()
    if not port:
        port = "7001"  # Default port for Wisenet Wave VMS

    # Prompt for username with default option
    username = input("Username (default admin, hit enter to use default): ").strip()
    if not username:
        username = "admin"  # Default admin account

    password = input("Password (visible input): ").strip()
    server_url = f"https://{server_ip}:{port}/rest/v3"
    return server_url, username, password


# Function to authenticate and get session token
def get_session_token(server_url, username, password):
    url = f"{server_url}/login/sessions"
    payload = {
        "username": username,
        "password": password
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers, verify=False)
    if response.status_code in [200, 201]:
        print("Session token obtained.")
        return response.json().get('token')
    else:
        print("Failed to obtain session token. Check credentials and server URL.")
        print("Response:", response.text)
        sys.exit(1)


# Function to check available licenses using summary
def check_available_licenses(server_url, token):
    url = f"{server_url}/licenses/*/summary"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        licenses_summary = response.json()

        # Aggregate total and available licenses across all types
        total_licenses = 0
        available_licenses = 0
        in_use = 0

        # Sum up all licenses
        for license_type, details in licenses_summary.items():
            total_licenses += details.get('total', 0)
            available_licenses += details.get('available', 0)
            in_use += details.get('inUse', 0)

        # Display aggregated license count
        print("\n[INFO] License Summary:")
        print(f"  Total Licenses: {total_licenses}")
        print(f"  Available Licenses: {available_licenses}")
        print(f"  In Use: {in_use}")

        # Check if there are any available licenses
        if available_licenses > 0:
            print("Sufficient licenses available.")
            return True
        else:
            print("Error: No available licenses. Add more licenses to enable recording.")
            return False
    else:
        print("Failed to retrieve license information.")
        print("Response:", response.text)
        return False


# Function to list all cameras and their details
def list_cameras(server_url, token):
    url = f"{server_url}/devices"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        devices = response.json()

        # Filter out cameras by checking deviceType
        cameras = []
        for device in devices:
            if device.get('deviceType') == 'Camera':
                camera_info = {
                    "name": device.get('name'),
                    "id": device.get('id'),
                    "physicalId": device.get('physicalId'),
                    "url": device.get('url'),
                    "typeId": device.get('typeId')
                }
                cameras.append(camera_info)

        # Display the filtered list of cameras with details
        print("\n[INFO] List of Cameras with Details:")
        for camera in cameras:
            print(f"Camera Name: {camera['name']}")
            print(f"  Camera ID: {camera['id']}")
            print(f"  Physical ID: {camera['physicalId']}")
            print(f"  Stream URL: {camera['url']}")
            print(f"  Type ID: {camera['typeId']}")
            print("-" * 40)

        if not cameras:
            print("\nError: No cameras found on the system. Exiting.")
            sys.exit(1)

        return cameras
    else:
        print("Failed to retrieve the list of cameras.")
        print("Response:", response.text)
        return []


# Function to prompt for recording type
def get_recording_type():
    print("\nSelect Recording Type:")
    print("  (A) Always")
    print("  (M) Motion Only")
    print("  (MLR) Motion and Low Res")
    print("  (OLR) Objects and Low Res")
    print("  (MOLR) Motion+Objects and Low Res (Default)")

    choice = input("Choose recording type (Default: MOLR): ").strip().upper()

    # Default to Motion+Objects and Low Res if enter is pressed
    if not choice:
        choice = "MOLR"

    # Mapping user choice to recording settings
    record_settings = {
        "A": {
            "metadataTypes": "none",
            "recordingType": "always"
        },
        "M": {
            "metadataTypes": "motion",
            "recordingType": "metadataOnly"
        },
        "MLR": {
            "metadataTypes": "motion",
            "recordingType": "metadataAndLowQuality"
        },
        "OLR": {
            "metadataTypes": "objects",
            "recordingType": "metadataAndLowQuality"
        },
        "MOLR": {
            "metadataTypes": "motion|objects",
            "recordingType": "metadataAndLowQuality"
        }
    }

    return record_settings.get(choice, record_settings["MOLR"])


# Function to enable recording by PATCHing the device with schedule
def enable_recording(server_url, camera, token, recording_type):
    url = f"{server_url}/devices/{camera['id']}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    schedule = {
        "isEnabled": True,
        "tasks": [
            {
                "dayOfWeek": day,
                "startTime": 0,
                "endTime": 86400,
                "fps": 15,
                "bitrateKbps": 0,
                "metadataTypes": recording_type["metadataTypes"],
                "recordingType": recording_type["recordingType"],
                "streamQuality": "normal"
            } for day in range(1, 8)
        ]
    }

    payload = {
        "id": camera['id'],
        "physicalId": camera['physicalId'],
        "url": camera['url'],
        "typeId": camera['typeId'],
        "isLicenseUsed": True,
        "schedule": schedule
    }

    print("\n[DEBUG] Sending PATCH Request to Enable Recording:")
    print("URL:", url)
    print("Headers:", headers)
    print("Payload:", json.dumps(payload, indent=4))

    response = requests.patch(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print(f"Recording enabled for camera {camera['name']}")
    else:
        print(f"Failed to enable recording for camera {camera['name']}. Status Code: {response.status_code}")
        print("Response:", response.text)


# Main function
def main():
    server_url, username, password = get_server_details()
    token = get_session_token(server_url, username, password)

    if not check_available_licenses(server_url, token):
        sys.exit(1)

    recording_type = get_recording_type()
    cameras = list_cameras(server_url, token)

    for camera in cameras:
        print(f"\nProcessing Camera: {camera['name']}")
        enable_recording(server_url, camera, token, recording_type)


if __name__ == "__main__":
    main()
