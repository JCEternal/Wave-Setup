# Wave Optimizer 1.1 - 3/4/25
# Created by JC
# Requires requests: pip install requests

# Checks Wave server for licenses, enables recording for all cameras at desired framerate,
# switches to H.265 codec, and enables Wisestream.
# Wisestream 3 is not available through Wave :(

# Script running video for first timers - https://youtu.be/W1CuoEo-Jtw

# ! python

import requests
import json
import sys
import logging
import csv
import os
import re

# Setup logging optimized for Windows CMD
logging.basicConfig(level=logging.INFO, format="%(message)s")

# Disable SSL warnings (for self-signed certificates)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


### **Helper Functions**

def get_valid_ip():
    """Prompt user for a valid IPv4 address."""
    while True:
        server_ip = input("Server IP Address: ").strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_ip):  # Check for four octets
            if all(0 <= int(octet) <= 255 for octet in server_ip.split(".")):  # Ensure valid range
                return server_ip
        print("⚠️ ERROR: Invalid IP address. Please enter a valid IPv4 address (e.g., 192.168.1.100).")


def get_confirmed_password():
    """Prompt user for a password and confirmation."""
    while True:
        password = input("Password (visible input): ").strip()
        confirm_password = input("Confirm Password: ").strip()
        if password == confirm_password:
            return password
        print("⚠️ ERROR: Passwords do not match. Please try again.")


def get_export_path():
    """Prompt user for a valid export directory."""
    while True:
        path = input("\nEnter directory to save results (e.g., C:\\logs) [Default: C:\\logs]: ").strip() or "C:\\logs"
        if os.path.exists(path):
            return path
        print("⚠️ ERROR: Invalid path. Please enter a valid existing directory.")


def get_server_details():
    """Prompt user for Wisenet Wave VMS server details."""
    print("\nEnter Wisenet Wave VMS server details:")
    server_ip = get_valid_ip()
    port = input("Port [Default: 7001]: ").strip() or "7001"
    username = input("Username [Default: admin]: ").strip() or "admin"
    password = get_confirmed_password()

    server_url = f"https://{server_ip}:{port}/rest/v3"
    return server_url, username, password


def get_session_token(server_url, username, password):
    """Authenticate and retrieve a session token."""
    url = f"{server_url}/login/sessions"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()

        token = response.json().get("token")
        logging.info("\n✅ Authentication successful. Session token obtained.")  # 🔥 Moved here immediately after authentication
        return token
    except requests.exceptions.RequestException as e:
        logging.error("\n❌ ERROR: Failed to obtain session token. Check credentials and server URL.")
        logging.error("Response: %s", response.text if response else str(e))
        sys.exit(1)



def list_cameras(server_url, token):
    """Retrieve all cameras from the VMS system."""
    url = f"{server_url}/devices"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        devices = response.json()

        cameras = [
            {"name": device.get("name"), "id": device.get("id")}
            for device in devices if device.get("deviceType") == "Camera"
        ]

        if not cameras:
            logging.error("\n❌ ERROR: No cameras found on the system.")
            sys.exit(1)

        return cameras
    except requests.exceptions.RequestException as e:
        logging.error("\n❌ ERROR: Failed to retrieve the list of cameras.")
        logging.error("Details: %s", str(e))
        sys.exit(1)


def get_fps():
    """Prompt user for FPS value. Default is 15."""
    while True:
        fps_input = input("\nEnter Frames Per Second (FPS) [Default: 15]: ").strip()
        if not fps_input:
            return 15
        try:
            fps = int(fps_input)
            if fps > 0:
                return fps
            print("⚠️ ERROR: FPS must be a positive number.")
        except ValueError:
            print("⚠️ ERROR: Invalid input. Please enter a number.")


def get_wisestream_mode():
    """Prompt user to enable Wisestream and select mode with default values."""
    enable_wisestream = input("\nEnable Wisestream? (y/n) [Default: y]: ").strip().lower() or "y"

    if enable_wisestream == "y":
        while True:
            mode = input(
                "Select Wisestream mode (Low/Medium/High) [Default: Medium]: ").strip().capitalize() or "Medium"
            if mode in ["Low", "Medium", "High"]:
                return mode
            print("⚠️ ERROR: Invalid choice. Please enter 'Low', 'Medium', or 'High'.")

    return "Off"


def get_recording_type():
    """Prompt user to select recording type."""
    print("\nSelect Recording Type:")
    print("  (A) Always")
    print("  (M) Motion Only")
    print("  (MLR) Motion and Low Res")
    print("  (OLR) Objects and Low Res")
    print("  (MOLR) Motion+Objects and Low Res (Default)")

    choice = input("Choose recording type (Default: MOLR): ").strip().upper() or "MOLR"

    return {
        "A": {"metadataTypes": "none", "recordingType": "always"},
        "M": {"metadataTypes": "motion", "recordingType": "metadataOnly"},
        "MLR": {"metadataTypes": "motion", "recordingType": "metadataAndLowQuality"},
        "OLR": {"metadataTypes": "objects", "recordingType": "metadataAndLowQuality"},
        "MOLR": {"metadataTypes": "motion|objects", "recordingType": "metadataAndLowQuality"},
    }.get(choice, {"metadataTypes": "motion|objects", "recordingType": "metadataAndLowQuality"})


def enable_recording(server_url, camera, token, recording_type, fps):
    """Enable recording by updating the schedule settings for the camera."""

    url = f"{server_url}/devices/{camera['id']}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    schedule = {
        "isEnabled": True,
        "tasks": [
            {
                "dayOfWeek": day,
                "startTime": 0,
                "endTime": 86400,
                "fps": fps,
                "metadataTypes": recording_type["metadataTypes"],
                "recordingType": recording_type["recordingType"],
                "streamQuality": "normal"
            }
            for day in range(1, 8)
        ]
    }

    payload = {"id": camera["id"], "schedule": schedule}

    logging.info(f"\n📹 Enabling recording for {camera['name']} at {fps} FPS")
    try:
        response = requests.patch(url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        logging.info(f"✅ Recording enabled for {camera['name']}")
    except requests.exceptions.RequestException as e:
        logging.error(f"\n❌ ERROR: Failed to enable recording for {camera['name']}. Details: {e}")


def change_codec_and_wisestream(server_url, camera_id, token, wisestream_mode):
    """Modify the camera codec to H.265 and update Wisestream mode if enabled."""

    url = f"{server_url}/devices/{camera_id}/advanced"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    payload = {
        "PRIMARY%media/videoprofile/EncodingType": "H265",
        "media/wisestream/Mode": wisestream_mode
    }

    logging.info(f"\n🔄 Updating camera: {camera_id} to H.265 & Wisestream mode: {wisestream_mode}")

    try:
        response = requests.patch(url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        logging.info(f"✅ Camera {camera_id}: Codec & Wisestream updated successfully.")
        return "Success"
    except requests.exceptions.RequestException as e:
        logging.error(f"\n❌ ERROR: Failed to update codec & Wisestream for {camera_id}. Details: {e}")
        return "Failed"

def save_results_to_csv(export_path, results):
    """Save camera processing results to a CSV file."""
    file_path = os.path.join(export_path, "WaveOptimizer_Results.csv")

    try:
        with open(file_path, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Camera Name", "Camera ID", "Codec Change", "Recording Enabled"])
            writer.writerows(results)

        logging.info(f"\n✅ Results saved to: {file_path}")
    except Exception as e:
        logging.error(f"\n❌ ERROR: Failed to save results to CSV. Details: {e}")


def main():
    """Main function to execute the script."""
    server_url, username, password = get_server_details()
    token = get_session_token(server_url, username, password)

    fps = get_fps()
    wisestream_mode = get_wisestream_mode()
    recording_type = get_recording_type()
    export_path = get_export_path()

    cameras = list_cameras(server_url, token)
    results = []

    for camera in cameras:
        logging.info(f"\n📷 Processing Camera: {camera['name']}")

        # Change codec & Wisestream mode
        codec_result = change_codec_and_wisestream(server_url, camera["id"], token, wisestream_mode)

        # Enable recording with selected settings
        enable_recording(server_url, camera, token, recording_type, fps)

        # Save results for CSV export
        results.append([camera["name"], camera["id"], codec_result])

    save_results_to_csv(export_path, results)


if __name__ == "__main__":
    main()
