from __future__ import annotations


def register(client, org_name: str, org_id: str, email: str):
    response = client.post(
        "/auth/register",
        json={
            "org_name": org_name,
            "org_id": org_id,
            "email": email,
            "password": "VeryStrongPass123!",
        },
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def human_headers(registration):
    return {
        "Authorization": f"Bearer {registration['token']}",
        "X-ORG-ID": registration["organization"]["org_id"],
    }


def test_header_alone_is_not_authentication(client):
    response = client.get("/devices", headers={"X-ORG-ID": "ACME"})
    assert response.status_code == 401


def test_tenant_membership_blocks_cross_org_reads(client):
    alpha = register(client, "Alpha", "ALPHA", "owner-alpha@example.com")
    register(client, "Beta", "BETA", "owner-beta@example.com")

    response = client.get(
        "/devices",
        headers={
            "Authorization": f"Bearer {alpha['token']}",
            "X-ORG-ID": "BETA",
        },
    )

    assert response.status_code == 403


def test_collector_enrollment_upload_idempotency_and_alert_lifecycle(client):
    owner = register(client, "Alpha", "ALPHA", "owner-alpha@example.com")
    headers = human_headers(owner)

    token_response = client.post(
        "/agent-enrollment-tokens",
        headers=headers,
        json={"ttl_minutes": 15},
    )
    assert token_response.status_code == 201
    enrollment_token = token_response.get_json()["enrollment_token"]

    enroll_response = client.post(
        "/agent/enroll",
        json={
            "enrollment_token": enrollment_token,
            "network": "Lab Network",
            "network_cidr": "10.0.0.0/24",
        },
    )
    assert enroll_response.status_code == 201, enroll_response.get_json()
    agent = enroll_response.get_json()

    collector_headers = {
        "X-API-Key": agent["api_key"],
        "X-ORG-ID": agent["org_id"],
    }

    heartbeat = client.post("/heartbeat", headers=collector_headers)
    assert heartbeat.status_code == 200

    payload = {
        "batch_id": "batch-test-001",
        "devices": [
            {"ip": "10.0.0.20", "mac": "AA:BB:CC:DD:EE:FF"},
        ],
    }

    first_upload = client.post("/upload", headers=collector_headers, json=payload)
    assert first_upload.status_code == 200, first_upload.get_json()
    assert first_upload.get_json()["devices_stored"] == 1

    retry_upload = client.post("/upload", headers=collector_headers, json=payload)
    assert retry_upload.status_code == 200
    assert retry_upload.get_json()["status"] == "duplicate_ignored"

    devices_response = client.get("/devices", headers=headers)
    assert devices_response.status_code == 200
    devices = devices_response.get_json()["devices"]
    assert len(devices) == 1
    assert devices[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    alerts_response = client.get("/alerts", headers=headers)
    assert alerts_response.status_code == 200
    alerts = alerts_response.get_json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["rule_key"] == "new_device"
    alert_id = alerts[0]["id"]

    ack = client.post(f"/alerts/{alert_id}/acknowledge", headers=headers)
    assert ack.status_code == 200
    assert ack.get_json()["status"] == "ACKNOWLEDGED"

    resolve = client.post(f"/alerts/{alert_id}/resolve", headers=headers)
    assert resolve.status_code == 200
    assert resolve.get_json()["status"] == "RESOLVED"


def test_login_uses_human_password_not_collector_api_key(client):
    register(client, "Alpha", "ALPHA", "owner-alpha@example.com")

    response = client.post(
        "/auth/login",
        json={"email": "owner-alpha@example.com", "password": "VeryStrongPass123!"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["token"]
    assert data["default_org_id"] == "ALPHA"
