from __future__ import annotations

import json
import os
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from dotenv import load_dotenv
import ipaddress

from scapy.all import conf

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from network_scanner import scan_network

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent
STATE_FILE = Path(os.getenv("NETWATCH_STATE_FILE", BASE_DIR / ".netwatch_agent.json"))
SPOOL_FILE = Path(os.getenv("NETWATCH_SPOOL_FILE", BASE_DIR / ".netwatch_spool.jsonl"))

API_URL = os.getenv("NETWATCH_API_URL", "http://127.0.0.1:5000").rstrip("/")
load_dotenv(BASE_DIR / ".env")
NETWORK_NAME = os.getenv("NETWATCH_NETWORK_NAME", "Local Network")
SCAN_RANGE_SETTING = os.getenv("NETWATCH_SCAN_RANGE", "auto").strip()
ENROLLMENT_TOKEN = os.getenv("NETWATCH_ENROLLMENT_TOKEN", "").strip()
SCAN_INTERVAL = max(10, int(os.getenv("NETWATCH_SCAN_INTERVAL", "30")))
HEARTBEAT_INTERVAL = max(10, int(os.getenv("NETWATCH_HEARTBEAT_INTERVAL", "30")))
REQUEST_TIMEOUT = max(3, int(os.getenv("NETWATCH_REQUEST_TIMEOUT", "10")))
VERIFY_TLS = os.getenv("NETWATCH_VERIFY_TLS", "true").lower() in {"1", "true", "yes", "on"}

STOP_REQUESTED = False

def _route_value_to_ipv4(value):
    if isinstance(value, int):
        return str(ipaddress.IPv4Address(value))

    return str(value)


def detect_active_ipv4_network():
    """
    Detect the IPv4 subnet used by the collector's active/default
    network interface.

    Returns:
        {
            "interface": "...",
            "ip": "172.16.23.242",
            "gateway": "172.16.23.1",
            "cidr": "172.16.23.0/24",
        }
    """

    # Refresh Scapy's view of the operating-system routing table.
    conf.route.resync()

    # Determine the interface used for ordinary outbound IPv4 traffic.
    interface, source_ip, gateway = conf.route.route("1.1.1.1")

    source = ipaddress.IPv4Address(source_ip)

    if source.is_loopback:
        raise RuntimeError("Detected loopback interface instead of an active network.")

    if source.is_link_local:
        raise RuntimeError(
            f"Detected link-local address {source_ip}; "
            "the collector does not appear to have a normal IPv4 connection."
        )

    if source.is_unspecified:
        raise RuntimeError("Unable to determine the collector's IPv4 address.")

    candidates = []

    for (
        network,
        netmask,
        route_gateway,
        route_interface,
        output_ip,
        metric,
    ) in conf.route.routes:

        if str(route_interface) != str(interface):
            continue

        try:
            network_address = _route_value_to_ipv4(network)
            netmask_address = _route_value_to_ipv4(netmask)

            candidate = ipaddress.IPv4Network(
                f"{network_address}/{netmask_address}",
                strict=False,
            )

        except ValueError:
            continue

        if source not in candidate:
            continue

        # Ignore the default route and host-only routes.
        if candidate.prefixlen == 0 or candidate.prefixlen >= 31:
            continue

        directly_connected = str(route_gateway) == "0.0.0.0"

        try:
            route_metric = int(metric or 0)
        except (TypeError, ValueError):
            route_metric = 0

        candidates.append(
            (
                1 if directly_connected else 0,
                candidate.prefixlen,
                -route_metric,
                candidate,
            )
        )

    if not candidates:
        raise RuntimeError(
            f"Could not determine the subnet for active IPv4 address {source_ip}."
        )

    _, _, _, selected_network = max(
        candidates,
        key=lambda item: (item[0], item[1], item[2]),
    )

    return {
        "interface": str(interface),
        "ip": str(source),
        "gateway": str(gateway),
        "cidr": str(selected_network),
    }


def get_network_context():
    """
    Use automatic detection by default.

    NETWATCH_SCAN_RANGE can still contain a CIDR to provide an explicit
    override during testing or unusual deployments.
    """

    if SCAN_RANGE_SETTING.lower() not in {"", "auto"}:
        network = ipaddress.IPv4Network(
            SCAN_RANGE_SETTING,
            strict=False,
        )

        interface, source_ip, gateway = conf.route.route(
            str(network.network_address + 1)
        )

        return {
            "interface": str(interface),
            "ip": str(source_ip),
            "gateway": str(gateway),
            "cidr": str(network),
        }

    return detect_active_ipv4_network()

def log(level: str, message: str, **fields: Any) -> None:
    payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "message": message,
        **fields,
    }
    print(json.dumps(payload, default=str), flush=True)


def handle_signal(_signum, _frame) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True
    log("INFO", "shutdown_requested")


def load_state() -> dict[str, str] | None:
    if not STATE_FILE.exists():
        return None
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    required = {"agent_id", "api_key", "org_id"}
    if not required.issubset(data):
        return None
    return data


def save_state(state: dict[str, str]) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    try:
        os.chmod(STATE_FILE, 0o600)
    except OSError:
        pass


def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        respect_retry_after_header=True,
    )
    session.mount("http://", HTTPAdapter(max_retries=retry))
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def enroll_agent() -> dict[str, str]:
    if not ENROLLMENT_TOKEN:
        raise RuntimeError(
            "This collector is not enrolled. Set NETWATCH_ENROLLMENT_TOKEN to a one-time token created in the NetWatch UI/API."
        )

    network_context = get_network_context()

    # Enrollment is deliberately not sent through the retrying session. If the
    # response is lost after the one-time token is consumed, create a fresh token.
    response = requests.post(
        f"{API_URL}/agent/enroll",
        json={
            "enrollment_token": ENROLLMENT_TOKEN,
            "network": NETWORK_NAME,
            "network_cidr": network_context["cidr"],
        },
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS,
    )
    response.raise_for_status()
    payload = response.json()

    state = {
        "agent_id": payload["agent_id"],
        "api_key": payload["api_key"],
        "org_id": payload["org_id"],
    }
    save_state(state)
    log("INFO", "collector_enrolled", agent_id=state["agent_id"], org_id=state["org_id"])
    return state


def auth_headers(state: dict[str, str]) -> dict[str, str]:
    return {
        "X-API-Key": state["api_key"],
        "X-ORG-ID": state["org_id"],
        "Content-Type": "application/json",
    }


def spool_payload(payload: dict[str, Any]) -> None:
    SPOOL_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SPOOL_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
    log("WARNING", "upload_spooled", batch_id=payload.get("batch_id"))


def send_upload(session: requests.Session, state: dict[str, str], payload: dict[str, Any]) -> None:
    response = session.post(
        f"{API_URL}/upload",
        json=payload,
        headers=auth_headers(state),
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS,
    )
    response.raise_for_status()
    log(
        "INFO",
        "upload_success",
        batch_id=payload.get("batch_id"),
        device_count=len(payload.get("devices", [])),
        response=response.json(),
    )


def flush_spool(session: requests.Session, state: dict[str, str]) -> None:
    if not SPOOL_FILE.exists():
        return

    lines = [line for line in SPOOL_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        SPOOL_FILE.unlink(missing_ok=True)
        return

    remaining: list[str] = []
    for index, line in enumerate(lines):
        try:
            payload = json.loads(line)
            send_upload(session, state, payload)
        except Exception as exc:
            remaining = lines[index:]
            log("WARNING", "spool_flush_paused", error=str(exc), remaining=len(remaining))
            break

    if remaining:
        temp_path = SPOOL_FILE.with_suffix(SPOOL_FILE.suffix + ".tmp")
        temp_path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
        temp_path.replace(SPOOL_FILE)
    else:
        SPOOL_FILE.unlink(missing_ok=True)
        log("INFO", "spool_flushed")


def send_heartbeat(
    session: requests.Session,
    state: dict[str, str],
    network_context: dict[str, str],
) -> None:
    response = session.post(
        f"{API_URL}/heartbeat",
        headers=auth_headers(state),
        json={
            "network": NETWORK_NAME,
            "network_cidr": network_context["cidr"],
            "agent_ip": network_context["ip"],
        },
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS,
    )

    response.raise_for_status()
    log("INFO", "heartbeat_success")


def run_agent() -> None:
    state = load_state() or enroll_agent()
    session = build_session()

    network_context = get_network_context()
    current_scan_range = network_context["cidr"]

    log(
        "INFO",
        "collector_started",
        api_url=API_URL,
        org_id=state["org_id"],
        agent_id=state["agent_id"],
        network=NETWORK_NAME,
        scan_range=current_scan_range,
        scan_interval=SCAN_INTERVAL,
    )

    last_heartbeat = 0.0

    while not STOP_REQUESTED:
        cycle_started = time.time()

        try:
            network_context = get_network_context()
            current_scan_range = network_context["cidr"]
        except Exception as exc:
            log("ERROR", "network_detection_failed", error=str(exc))
            time.sleep(5)
            continue

        try:
            flush_spool(session, state)
        except Exception as exc:
            log("WARNING", "spool_flush_error", error=str(exc))

        if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL:
            try:
                send_heartbeat(session, state, network_context)
                last_heartbeat = time.time()
            except Exception as exc:
                log("WARNING", "heartbeat_failed", error=str(exc))

        try:
            scan_started = time.time()

            devices = scan_network(current_scan_range)

            scan_seconds = round(time.time() - scan_started, 2)

            payload = {
                "batch_id": str(uuid.uuid4()),
                "network": NETWORK_NAME,
                "network_cidr": network_context["cidr"],
                "agent_ip": network_context["ip"],
                "observed_at": time.time(),
                "devices": devices,
            }

            log("INFO", "scan_complete", device_count=len(devices), duration_seconds=scan_seconds)

            try:
                send_upload(session, state, payload)
            except Exception as exc:
                log("WARNING", "upload_failed", error=str(exc), batch_id=payload["batch_id"])
                spool_payload(payload)

        except PermissionError as exc:
            log(
                "ERROR",
                "scan_permission_error",
                error=str(exc),
                hint="Scapy ARP scanning requires administrator/root packet privileges.",
            )
        except Exception as exc:
            log("ERROR", "scan_failed", error=str(exc))

        elapsed = time.time() - cycle_started
        sleep_for = max(1, SCAN_INTERVAL - elapsed)
        deadline = time.time() + sleep_for
        while not STOP_REQUESTED and time.time() < deadline:
            time.sleep(min(1, deadline - time.time()))

    log("INFO", "collector_stopped")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    try:
        run_agent()
    except requests.HTTPError as exc:
        log("ERROR", "collector_http_fatal", error=str(exc), response=getattr(exc.response, "text", None))
        sys.exit(1)
    except Exception as exc:
        log("ERROR", "collector_fatal", error=str(exc))
        sys.exit(1)
