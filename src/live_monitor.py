import time
from network_scanner import scan_network, load_baseline, save_baseline
from alerts import detect_new_devices

TARGET_NETWORK = "192.168.1.1/24"
SCAN_INTERVAL = 10


def run_live_monitor():
    print("Starting NetWatch Live Monitoring Mode...\n")

    while True:
        print("Scanning network...")

        current_devices = scan_network(TARGET_NETWORK)
        baseline_devices = load_baseline()

        new_devices = detect_new_devices(current_devices, baseline_devices)

        if not new_devices:
            print("No new devices detected.\n")

        save_baseline(current_devices)

        print(f"Waiting {SCAN_INTERVAL} seconds...\n")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run_live_monitor()