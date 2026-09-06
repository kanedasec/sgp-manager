import os

import pytest


@pytest.fixture
def webhook_capture(monkeypatch):
    """Force synchronous, in-process audit webhook delivery and capture every
    payload handed to httpx.post, without making a real network call."""
    from app.services import audit_sink
    from app.core.config import get_settings

    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "https://siem.example.com/ingest")
    monkeypatch.setenv("AUDIT_WEBHOOK_SECRET", "a-shared-secret-for-hmac-signing")
    monkeypatch.setenv("AUDIT_WEBHOOK_DELIVER_SYNCHRONOUSLY", "true")
    get_settings.cache_clear()

    captured = []

    class FakeResponse:
        status_code = 200

    def fake_post(url, content, headers, timeout):
        import json
        captured.append(json.loads(content))
        return FakeResponse()

    monkeypatch.setattr(audit_sink.httpx, "post", fake_post)
    yield captured
    get_settings.cache_clear()


def test_admin_action_delivers_a_signed_webhook_after_commit(client, admin_headers, webhook_capture):
    response = client.post(
        "/api/v1/admin/owners", headers=admin_headers,
        json={"name": "AppSec", "slug": "appsec", "description": "Application security ownership."},
    )
    assert response.status_code == 201
    assert len(webhook_capture) == 1
    assert webhook_capture[0]["event_type"] == "OWNER_CREATED"
    assert webhook_capture[0]["metadata"]["slug"] == "appsec"


def test_failed_write_never_delivers_a_webhook(client, admin_headers, webhook_capture):
    # Duplicate slug: the second create fails and rolls back its transaction.
    first = client.post(
        "/api/v1/admin/owners", headers=admin_headers,
        json={"name": "AppSec", "slug": "appsec", "description": "Application security ownership."},
    )
    assert first.status_code == 201
    webhook_capture.clear()

    duplicate = client.post(
        "/api/v1/admin/owners", headers=admin_headers,
        json={"name": "AppSec Duplicate", "slug": "appsec", "description": "Should conflict."},
    )
    assert duplicate.status_code == 409
    assert webhook_capture == []


def test_metrics_endpoint_exposes_business_counters_and_state(client, admin_headers):
    client.post(
        "/api/v1/admin/owners", headers=admin_headers,
        json={"name": "AppSec", "slug": "appsec", "description": "Application security ownership."},
    )
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.text
    assert "sgp_business_events_total" in body
    assert 'event_type="OWNER_CREATED"' in body
    assert "sgp_applications_total" in body
    assert "sgp_gates_total" in body
    assert "sgp_active_bypass_policies" in body


def test_metrics_endpoint_records_enforcement_decisions(client, domain, api_key):
    key, _ = api_key
    response = client.post(
        "/api/v1/policies/evaluate-enforcement", headers={"X-API-Key": key},
        json={"application": "payment-api"},
    )
    assert response.status_code == 200
    metrics = client.get("/metrics")
    assert "sgp_enforcement_decisions_total" in metrics.text
    assert 'gate="secrets"' in metrics.text
