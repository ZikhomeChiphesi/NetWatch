from scapy.all import ARP, Ether, srp
import json
import os

BASELINE_FILE = "baseline_devices.json"


def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []

    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return []
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def save_baseline(devices):
    with open(BASELINE_FILE, "w") as f:
        json.dump(devices, f, indent=4)


def find_new_devices(current, baseline):
    baseline_macs = [d["mac"] for d in baseline]
    new_devices = []

    for device in current:
        if device["mac"] not in baseline_macs:
            new_devices.append(device)

    return new_devices


if __name__ == "__main__":
    target = "192.168.1.1/24"

    print("Scanning network...\n")

    current_devices = scan_network(target)
    baseline_devices = load_baseline()

    new_devices = find_new_devices(current_devices, baseline_devices)

    print("Devices found:")
    for d in current_devices:
        print(d["ip"], d["mac"])

    print("\nNew devices:")

    with open("../logs/new_devices.txt", "a") as f:
        for d in new_devices:
            line = f"{d['ip']} {d['mac']}\n"
            print(line.strip())
            f.write(line)

    save_baseline(current_devices)