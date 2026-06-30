import wmi
import socket
import platform
import requests
import subprocess
import sys

def register_scheduled_tasks():
    exe_path = sys.executable

    try:
        # Trigger 1: run at system startup, under SYSTEM account
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

    try:
        # Trigger 2: recurring every 2 minutes, as a safety net
        subprocess.run([
            "schtasks", "/Create",
            "/SC", "MINUTE",
            "/MO", "2",
            "/TN", "EAM_Agent_Recurring",
            "/TR", exe_path,
            "/F"
        ], check=True, capture_output=True, text=True)
        print("Recurring task registered successfully.")
    except subprocess.CalledProcessError as e:
        print("Failed to register recurring task:", e.stderr)


def send_heartbeat():
    c = wmi.WMI()

    bios = c.Win32_BIOS()[0]
    product = c.Win32_ComputerSystemProduct()[0]

    mac_address = None
    for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        mac_address = nic.MACAddress
        break

    payload = {
        "serial_number": bios.SerialNumber,
        "uuid": product.UUID,
        "hostname": socket.gethostname(),
        "os_version": platform.platform(),
        "mac_address": mac_address
    }

    print("Sending payload:", payload)

    try:
        response = requests.post("http://127.0.0.1:5000/heartbeat", json=payload, timeout=10)
        print("Server response:", response.status_code, response.json())
    except requests.exceptions.RequestException as e:
        print("Failed to send heartbeat:", e)


if __name__ == "__main__":
    register_scheduled_tasks()
    send_heartbeat()