# Created by JC with the help of GTP-4o
# Updated: March 4, 2025

# ! python
import requests
import json
import sys
import logging

# Setup logging optimized for Windows CMD
logging.basicConfig(level=logging.INFO, format="%(message)s")

# Disable SSL warnings (for self-signed certificates)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def get_server_details():
    """Prompt user for Wisenet Wave VMS server details."""
    print("\nEnter Wisenet Wave VMS server details:")
    server_ip = input("Server IP Address: ").strip()

    port = input("Port [Default: 7001]: ").strip() or "7001"
    username = input("Username [Default: admin]: ").strip() or "admin"
    password = input("Password (visible input): ").strip()

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
        logging.info("✅ Authentication successful. Session token obtained.")
        return response.json().get("token")
    except requests.exceptions.RequestException as e:
        logging.error("\n❌ ERROR: Failed to obtain session token. Check credentials and server URL.")
        logging.error("Response: %s", response.text if response else str(e))
        sys.exit(1)


def check_available_licenses(server_url, token):
    """Check available licenses using summary."""
    url = f"{server_url}/licenses/*/summary"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        licenses_summary = response.json()

        total_licenses = sum(details.get("total", 0) for details in licenses_summary.values())
        available_licenses = sum(details.get("available", 0) for details in licenses_summary.values())

        logging.info(f"\n📊 License Summary - Total: {total_licenses}, Available: {available_licenses}")

        return available_licenses > 0
    except requests.exceptions.RequestException as e:
        logging.error("\n❌ ERROR: Failed to retrieve license information.")
        logging.error("Details: %s", str(e))
        return False


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
            return 15  # Default FPS
        try:
            fps = int(fps_input)
            if fps > 0:
                return fps
            else:
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


def change_codec_and_wisestream(server_url, camera_id, token, wisestream_mode):
    """Modify the camera codec to H.265 and update Wisestream mode if enabled."""

    camera_id = camera_id.strip("{}")  # Remove unnecessary brackets

    url = f"{server_url}/devices/{camera_id}/advanced"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    payload = {
        "PRIMARY%media/videoprofile/EncodingType": "H265",
        "media/wisestream/Mode": wisestream_mode
    }

    logging.info(f"\n🔄 Changing codec to H.265 and Wisestream mode to {wisestream_mode} for camera: {camera_id}")

    try:
        response = requests.patch(url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        logging.info(f"✅ Codec & Wisestream mode updated successfully for camera: {camera_id}")
    except requests.exceptions.RequestException as e:
        logging.error(f"\n❌ ERROR: Failed to update codec & Wisestream mode for camera {camera_id}.")
        logging.error("Details: %s", str(e))


def enable_recording(server_url, camera, token, fps):
    """Enable recording by PATCHing the device with schedule."""
    url = f"{server_url}/devices/{camera['id']}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    schedule = {
        "isEnabled": True,
        "tasks": [
            {"dayOfWeek": day, "startTime": 0, "endTime": 86400, "fps": fps, "recordingType": "always"}
            for day in range(1, 8)
        ]
    }

    payload = {"id": camera["id"], "schedule": schedule}

    logging.info(f"\n📹 Enabling recording for camera: {camera['name']} at {fps} FPS")

    try:
        response = requests.patch(url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        logging.info(f"✅ Recording enabled for camera: {camera['name']}")
    except requests.exceptions.RequestException as e:
        logging.error(f"\n❌ ERROR: Failed to enable recording for camera {camera['name']}.")
        logging.error("Details: %s", str(e))


def main():
    """Main function to execute the script."""
    server_url, username, password = get_server_details()
    token = get_session_token(server_url, username, password)

    if not check_available_licenses(server_url, token):
        sys.exit(1)

    fps = get_fps()
    wisestream_mode = get_wisestream_mode()
    cameras = list_cameras(server_url, token)

    for camera in cameras:
        logging.info(f"\n📷 Processing Camera: {camera['name']}")
        change_codec_and_wisestream(server_url, camera["id"], token, wisestream_mode)
        enable_recording(server_url, camera, token, fps)


if __name__ == "__main__":
    main()
