import wmi
import socket
import platform
import requests

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

response = requests.post("http://127.0.0.1:5000/heartbeat", json=payload)

print("Server response:", response.status_code, response.json())