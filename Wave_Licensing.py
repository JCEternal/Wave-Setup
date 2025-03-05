# Wave Licensing 1.0 3/2/25
# Created by JC
# Needs requests installed, pip install requests

# Simply copy and paste all the license data (not need to truncate any information, the script cleans it up), run the
# script, input the data and license the system quickly!!!

# Script running video for first timers - https://youtu.be/W1CuoEo-Jtw


import re
import sys
import requests
from requests.exceptions import RequestException

# Disable SSL warnings for local server connections
requests.packages.urllib3.disable_warnings()


def get_user_inputs():
    """
    Prompt the user for WAVE server details and license file path.
    """
    server_ip = input("Enter WAVE Server IP Address: ")
    server_port = input("Enter WAVE Server Port (Press Enter for default 7001): ") or "7001"
    server_username = input("Enter WAVE Server Username (Press Enter for default 'admin'): ") or "admin"
    server_password = input("Enter WAVE Server Password: ")  # Password is shown on screen
    licenses_file_path = input("Enter the full path for the licenses.txt file (e.g., C:\\Temp\\licenses.txt): ")

    wave_server_url = f"https://{server_ip}:{server_port}"

    return wave_server_url, server_username, server_password, licenses_file_path


def check_user_type(wave_server_url, username):
    """
    Check the user type on the WAVE server.
    """
    url = f"{wave_server_url}/rest/v3/login/users/{username}"

    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()
        user_info = response.json()
        user_type = user_info.get('type')
        methods = user_info.get('methods')

        if user_type in ['local', 'ldap'] and 'sessions' in methods:
            print(f"User type confirmed as '{user_type}' with session method available.")
            return True
        else:
            print("Error: This user type is not allowed to use session tokens.")
            sys.exit(1)
    except RequestException as e:
        print(f"Error checking user type: {e}")
        sys.exit(1)


def authenticate(wave_server_url, username, password):
    """
    Authenticate to the WAVE server and return the session token.
    """
    if not check_user_type(wave_server_url, username):
        print("Error: User type not allowed for session token authentication.")
        sys.exit(1)

    url = f"{wave_server_url}/rest/v3/login/sessions"
    payload = {
        "username": username,
        "password": password
    }

    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        token = response.json().get('token')
        if not token:
            print("Error: Authentication failed. No session token received.")
            sys.exit(1)
        print("Authentication successful. Session token obtained.")
        return token
    except RequestException as e:
        print(f"Error during authentication: {e}")
        print(f"Response Text: {response.text}")
        sys.exit(1)


def create_license(wave_server_url, token, license_key):
    """
    Create a license on the WAVE server using the extracted license key.
    """
    if not license_key:
        print("Warning: Empty license key encountered. Skipping.")
        return

    url = f"{wave_server_url}/rest/v3/licenses/{license_key}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    body = {
        "key": license_key
    }

    print(f"\nCreating License for Key: {license_key}")
    print(f"Request URL: {url}")
    print(f"Request Headers: {headers}")
    print(f"Request Body: {body}")

    try:
        response = requests.put(url, json=body, headers=headers, verify=False)
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")

        if response.status_code in [200, 201]:
            print(f"License created successfully for key: {license_key}")
        elif response.status_code == 409:
            print(f"License already exists for key: {license_key}")
        else:
            print(f"Failed to create license for key {license_key}. Status Code: {response.status_code}")
    except RequestException as e:
        print(f"Error creating license for key {license_key}: {e}")


def read_licenses(file_path):
    """
    Read the licenses text file from a user-defined path, print each line, and extract the license keys.
    """
    license_keys = []
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            print(f"\nContents of {file_path}:")
            for line in lines:
                print(line.strip())
                match = re.search(r'Key #[\d]+: ([A-Z0-9\-]+)', line)
                if match:
                    license_key = match.group(1)
                    license_keys.append(license_key)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading licenses file: {e}")
        sys.exit(1)

    return license_keys


def print_licenses(license_keys):
    """
    Print the extracted license keys.
    """
    print("\nExtracted License Keys:")
    for i, key in enumerate(license_keys, start=1):
        print(f"License {i}: {key}")


def main():
    wave_server_url, server_username, server_password, licenses_file_path = get_user_inputs()

    license_keys = read_licenses(licenses_file_path)
    print_licenses(license_keys)

    token = authenticate(wave_server_url, server_username, server_password)

    for license_key in license_keys:
        create_license(wave_server_url, token, license_key)


if __name__ == "__main__":
    main()
