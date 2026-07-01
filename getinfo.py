import wmi
import socket
import platform
import requests
import subprocess
import sys
import os

def register_scheduled_tasks():
    exe_path = sys.executable

    # Check and register startup task only if it doesn't exist
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", "EAM_Agent_Startup"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        try:
            subprocess.run([
                "schtasks", "/Create",
                "/SC", "ONSTART",
                "/RU", "SYSTEM",
                "/TN", "EAM_Agent_Startup",
                "/TR", exe_path,
                "/F"
            ], check=True, capture_output=True, text=True)
            print("Startup task registered successfully.")
        except subprocess.CalledProcessError as e:
            print("Failed to register startup task:", e.stderr)
    else:
        print("Startup task already exists, skipping.")

    # Check and register recurring task only if it doesn't exist
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", "EAM_Agent_Recurring"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        try:
            subprocess.run([
                "schtasks", "/Create",
                "/SC", "MINUTE",
                "/MO", "2",
                "/RU", "SYSTEM",
                "/TN", "EAM_Agent_Recurring",
                "/TR", exe_path,
                "/F"
            ], check=True, capture_output=True, text=True)
            print("Recurring task registered successfully.")
        except subprocess.CalledProcessError as e:
            print("Failed to register recurring task:", e.stderr)
    else:
        print("Recurring task already exists, skipping.")


def send_heartbeat():
    try:
        c = wmi.WMI()

        bios = c.Win32_BIOS()[0]
        product = c.Win32_ComputerSystemProduct()[0]

        mac_address = None
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            mac_address = nic.MACAddress
            break

        # Get WiFi SSID
        ssid = None
        try:
            ssid_result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True
            )
            for line in ssid_result.stdout.split("\n"):
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":")[1].strip()
                    break
        except Exception:
            ssid = "Unknown"

        # Get currently logged in username
        logged_in_user = os.environ.get("USERNAME", "Unknown")

        payload = {
            "serial_number": bios.SerialNumber,
            "uuid": product.UUID,
            "hostname": socket.gethostname(),
            "os_version": platform.platform(),
            "mac_address": mac_address,
            "ssid": ssid,
            "logged_in_user": logged_in_user
        }

        print("Sending payload:", payload)

        response = requests.post(
            "http://127.0.0.1:5000/heartbeat",
            json=payload,
            timeout=10
        )
        print("Server response:", response.status_code, response.json())

    except Exception as e:
        print("Error during heartbeat:", e)


if __name__ == "__main__":
    register_scheduled_tasks()
    send_heartbeat()