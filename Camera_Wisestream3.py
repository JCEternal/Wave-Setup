# Wave Camera Optimizer Part II v1.0
# Created by JC
# Needs requests and pandas installed, pip install requests pandas

# Reads WDM export and sets Wisestream 3 to on and if the level is none it sets the level
# to medium.  Also will change Sharpness if you want extra BW savings.

# Script running video for first timers - https://youtu.be/W1CuoEo-Jtw

import os
import requests
from requests.auth import HTTPDigestAuth
import ipaddress
import pandas as pd


def valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def parse_key_value_response(text):
    lines = text.splitlines()
    parsed = {}
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key.strip()] = value.strip()
    return parsed


def get_wisestream_info(ip, username, password, timeout=10):
    url = f"http://{ip}/stw-cgi/media.cgi?msubmenu=wisestream&action=view"
    response = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=timeout)
    response.raise_for_status()
    try:
        return response.json()
    except Exception:
        return parse_key_value_response(response.text)


def get_imageenhancements_info(ip, username, password, timeout=10):
    url = f"http://{ip}/stw-cgi/image.cgi?msubmenu=imageenhancements&action=view"
    response = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=timeout)
    response.raise_for_status()
    try:
        return response.json()
    except Exception:
        return parse_key_value_response(response.text)


def set_aisupport_enable(ip, username, password, channel=None, timeout=10):
    url = f"http://{ip}/stw-cgi/media.cgi?msubmenu=wisestream&action=set&AISupportEnable=True"
    if channel is not None:
        url += f"&Channel={channel}"
    response = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=timeout)
    response.raise_for_status()
    return response.text


def set_sharpness(ip, username, password, value, channel=None, timeout=10):
    url = f"http://{ip}/stw-cgi/image.cgi?msubmenu=imageenhancements&action=set&SharpnessLevel={value}"
    if channel is not None:
        url += f"&Channel={channel}"
    response = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=timeout)
    response.raise_for_status()
    return response.text


def set_mode(ip, username, password, value, channel=None, timeout=10):
    url = f"http://{ip}/stw-cgi/media.cgi?msubmenu=wisestream&action=set&Mode={value}"
    if channel is not None:
        url += f"&Channel={channel}"
    response = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=timeout)
    response.raise_for_status()
    return response.text


def process_camera_sensor(ip, username, password, sensor_channel, target_sharpness=None):
    """Process one sensor and return True on success, False on failure."""
    success = True
    try:
        wisestream_info = get_wisestream_info(ip, username, password)
    except Exception:
        return False

    # JSON multisensor response
    if isinstance(wisestream_info, dict) and "WiseStream" in wisestream_info and isinstance(
            wisestream_info["WiseStream"], list):
        sensor_found = None
        for sensor in wisestream_info["WiseStream"]:
            if sensor.get("Channel") == sensor_channel:
                sensor_found = sensor
                break
        if sensor_found is None:
            return False

        # If Mode is "Off", set it to "Medium"
        if str(sensor_found.get("Mode")).lower() == "off":
            try:
                set_mode(ip, username, password, "Medium", channel=sensor_channel)
            except Exception:
                success = False

        # Ensure AISupportEnable is True
        if not (isinstance(sensor_found.get("AISupportEnable"), bool) and sensor_found.get("AISupportEnable")):
            try:
                set_aisupport_enable(ip, username, password, channel=sensor_channel)
            except Exception:
                success = False

        # Set Sharpness if requested
        if target_sharpness:
            try:
                set_sharpness(ip, username, password, target_sharpness, channel=sensor_channel)
            except Exception:
                success = False

        # Re-read final settings for sharpness from ImageEnhancements endpoint.
        try:
            final_image = get_imageenhancements_info(ip, username, password)
            final_sharp = "N/A"
            if isinstance(final_image, dict) and "ImageEnhancements" in final_image and isinstance(
                    final_image["ImageEnhancements"], list):
                for entry in final_image["ImageEnhancements"]:
                    if entry.get("Channel") == sensor_channel:
                        final_sharp = entry.get("SharpnessLevel", "N/A")
                        break
            # Optionally, you might check final_mode and final AISupportEnable as well.
        except Exception:
            success = False

    # Key‐value format branch (not likely with modern devices)
    elif isinstance(wisestream_info, dict):
        sensor_prefix = f"Channel.{sensor_channel}."
        if sensor_prefix + "Mode" not in wisestream_info:
            return False
        if str(wisestream_info.get(sensor_prefix + "Mode", "")).lower() == "off":
            try:
                set_mode(ip, username, password, "Medium", channel=sensor_channel)
            except Exception:
                success = False
        if str(wisestream_info.get(sensor_prefix + "AISupportEnable", "")).lower() != "true":
            try:
                set_aisupport_enable(ip, username, password, channel=sensor_channel)
            except Exception:
                success = False
        if target_sharpness:
            try:
                set_sharpness(ip, username, password, target_sharpness, channel=sensor_channel)
            except Exception:
                success = False
    else:
        success = False

    return success


def main():
    folder_location = input("Enter folder location (default: c:\\reports): ").strip() or "c:\\reports"
    file_name = input("Enter full file name (default: wdm.xlsx): ").strip() or "wdm.xlsx"
    full_path = os.path.join(folder_location, file_name)

    try:
        df = pd.read_excel(full_path)
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        return

    ip_column = None
    channel_column = None
    for col in df.columns:
        lower = col.strip().lower()
        if lower == "ip address":
            ip_column = col
        elif lower == "channel":
            channel_column = col

    if ip_column is None:
        ip_column = df.columns[0]
    if channel_column is None:
        print("Channel column not found in the Excel file. Exiting.")
        return

    rows = df[[ip_column, channel_column]].dropna()
    if rows.empty:
        print("No valid rows with IP Address and Channel found.")
        return

    username = input("Enter username (default 'admin'): ").strip() or "admin"
    password = input("Enter password: ").strip()
    if not password:
        print("Password is required. Exiting.")
        return

    valid_rows = rows[rows[ip_column].apply(lambda ip: valid_ip(str(ip).strip()))]
    if valid_rows.empty:
        print("No valid IP addresses found in the file.")
        return
    test_ip = str(valid_rows.iloc[0][ip_column]).strip()
    while True:
        try:
            _ = get_wisestream_info(test_ip, username, password)
            confirm = input("Does the password appear to be correct? (y/n): ").strip().lower()
            if confirm in ["y", "yes"]:
                break
            else:
                password = input("Re-enter password: ").strip()
                if not password:
                    print("Password is required. Exiting.")
                    return
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                retry = input("Authentication failed. Is your password correct? (y/n): ").strip().lower()
                if retry in ["y", "yes"]:
                    password = input("Re-enter password: ").strip()
                    if not password:
                        print("Password is required. Exiting.")
                        return
                else:
                    print("Exiting due to authentication failure.")
                    return
        except Exception as e:
            print(f"An error occurred while checking credentials: {e}")
            return

    sharpness_choice = input(
        "Enter desired sharpness saving level (l for low=10, m for medium=8, h for high=6, leave blank to skip): ").strip().lower()
    target_sharpness = None
    if sharpness_choice == 'l':
        target_sharpness = "10"
    elif sharpness_choice == 'm':
        target_sharpness = "8"
    elif sharpness_choice == 'h':
        target_sharpness = "6"

    print("\nProcessing cameras...\n" + "=" * 40)
    for _, row in rows.iterrows():
        ip_addr = str(row[ip_column]).strip()
        channel_raw = str(row[channel_column]).strip()
        if channel_raw.strip().lower() == "single":
            sensor_channel = 0
        else:
            try:
                if channel_raw.upper().startswith("CH"):
                    channel_num = int(channel_raw[2:])
                else:
                    channel_num = int(channel_raw)
                sensor_channel = channel_num - 1
            except Exception:
                print(f"{ip_addr} (Channel: {channel_raw}): Failure (invalid channel)")
                continue

        if not valid_ip(ip_addr):
            print(f"{ip_addr}: Failure (invalid IP)")
            continue

        result = process_camera_sensor(ip_addr, username, password, sensor_channel, target_sharpness)
        if result:
            print(f"{ip_addr} (Channel {sensor_channel}): Success")
        else:
            print(f"{ip_addr} (Channel {sensor_channel}): Failure")


if __name__ == "__main__":
    main()
