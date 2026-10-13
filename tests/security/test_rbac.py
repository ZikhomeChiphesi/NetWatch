from __future__ import annotations

import os

import psycopg2
import pytest


PASSWORD = "VeryStrongPass123!"


def register(client, org_name: str, org_id: str, email: str):
    response = client.post(
        "/auth/register",
        json={
            "org_name": org_name,
            "org_id": org_id,
            "email": email,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 201, response.get_json()
    return response.get_json()


def human_headers(registration):
    return {
        "Authorization": f"Bearer {registration['token']}",
        "X-ORG-ID": registration["organization"]["org_id"],
    }


def set_membership_role(org_id: str, email: str, role: str):
    conn = psycopg2.connect(os.environ["DATABASE_URL"])

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE org_memberships
                SET role = %s
                WHERE org_id = %s
                  AND user_id = (
                      SELECT user_id
                      FROM users
                      WHERE email = %s
                  )
                """,
                (role, org_id, email),
            )

            assert cur.rowcount == 1

        conn.commit()

    finally:
        conn.close()


def test_owner_can_create_agent_enrollment_token(client):
    email = "owner@example.com"

    registration = register(
        client,
        "Alpha",
        "ALPHA",
        email,
    )

    response = client.post(
        "/agent-enrollment-tokens",
        headers=human_headers(registration),
        json={"ttl_minutes": 15},
    )

    assert response.status_code == 201
    assert response.get_json()["enrollment_token"]


def test_admin_can_create_agent_enrollment_token(client):
    email = "admin@example.com"

    registration = register(
        client,
        "Alpha",
        "ALPHA",
        email,
    )

    set_membership_role(
        "ALPHA",
        email,
        "ADMIN",
    )

    response = client.post(
        "/agent-enrollment-tokens",
        headers=human_headers(registration),
        json={"ttl_minutes": 15},
    )

    assert response.status_code == 201


@pytest.mark.parametrize(
    "role",
    [
        "OPERATOR",
        "VIEWER",
    ],
)
def test_operator_and_viewer_cannot_create_agent_enrollment_token(
    client,
    role,
):
    email = f"{role.lower()}@example.com"

    registration = register(
        client,
        "Alpha",
        "ALPHA",
        email,
    )

    set_membership_role(
        "ALPHA",
        email,
        role,
    )

    response = client.post(
        "/agent-enrollment-tokens",
        headers=human_headers(registration),
        json={"ttl_minutes": 15},
    )

    assert response.status_code == 403


def test_operator_is_authorized_for_alert_actions(client):
    email = "operator@example.com"

    registration = register(
        client,
        "Alpha",
        "ALPHA",
        email,
    )

    set_membership_role(
        "ALPHA",
        email,
        "OPERATOR",
    )

    response = client.post(
        "/alerts/999999/acknowledge",
        headers=human_headers(registration),
    )

    # 404 proves authorization succeeded and the request
    # reached the handler; the test alert simply does not exist.
    assert response.status_code == 404


def test_viewer_cannot_modify_alerts(client):
    email = "viewer@example.com"

    registration = register(
        client,
        "Alpha",
        "ALPHA",
        email,
    )

    set_membership_role(
        "ALPHA",
        email,
        "VIEWER",
    )

    response = client.post(
        "/alerts/999999/acknowledge",
        headers=human_headers(registration),
    )

    assert response.status_code == 403


def test_viewer_can_access_read_only_device_inventory(client):
    email = "viewer-read@example.com"

    registration = register(
        client,
        "Alpha",
        "ALPHA",
        email,
    )

    set_membership_role(
        "ALPHA",
        email,
        "VIEWER",
    )

    response = client.get(
        "/devices",
        headers=human_headers(registration),
    )

    assert response.status_code == 200