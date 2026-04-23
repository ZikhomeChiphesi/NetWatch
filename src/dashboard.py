import time
from rich.console import Console
from rich.table import Table
from network_scanner import scan_network

console = Console()

TARGET_NETWORK = "192.168.1.1/24"
SCAN_INTERVAL = 10


def display_dashboard(devices):
    table = Table(title="NetWatch Live Dashboard")

    table.add_column("IP", style="cyan")
    table.add_column("MAC Address", style="magenta")

    for d in devices:
        table.add_row(d["ip"], d["mac"])

    console.clear()
    console.print(table)


def run_dashboard():
    console.print("[bold green]Starting NetWatch Dashboard Mode...[/bold green]")

    while True:
        devices = scan_network(TARGET_NETWORK)
        display_dashboard(devices)

        console.print(f"\nRefreshing in {SCAN_INTERVAL} seconds...")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run_dashboard()