import time
from rich.console import Console
from rich.table import Table
from network_scanner import scan_network, load_baseline
from threat_engine import analyze_device

console = Console()

TARGET_NETWORK = "192.168.1.1/24"
SCAN_INTERVAL = 10


def display_dashboard(devices, known_devices):
    table = Table(title="NetWatch Security Dashboard")

    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("RISK", style="red")
    table.add_column("SCORE")

    for d in devices:
        result = analyze_device(d, known_devices)

        table.add_row(
            result["ip"],
            result["mac"],
            result["level"],
            str(result["score"])
        )

    console.clear()
    console.print(table)


def run_dashboard():
    console.print("[bold green]Starting NetWatch Dashboard Mode...[/bold green]")

    while True:
        known_devices = load_baseline()
        devices = scan_network(TARGET_NETWORK)
        display_dashboard(devices, known_devices)

        console.print(f"\nRefreshing in {SCAN_INTERVAL} seconds...")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run_dashboard()