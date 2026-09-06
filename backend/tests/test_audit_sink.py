import hashlib
import hmac
import json

import pytest

from app.services import audit_sink


@pytest.fixture(autouse=True)
def reset_settings_cache():
    from app.core.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_deliver_is_a_noop_without_webhook_url(monkeypatch):
    monkeypatch.delenv("AUDIT_WEBHOOK_URL", raising=False)
    from app.core.config import get_settings
    get_settings.cache_clear()
    assert audit_sink.deliver({"id": "x"}) is False


def test_deliver_signs_the_body_and_succeeds_on_2xx(monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "https://siem.example.com/ingest")
    monkeypatch.setenv("AUDIT_WEBHOOK_SECRET", "a-shared-secret-for-hmac-signing")
    from app.core.config import get_settings
    get_settings.cache_clear()

    captured = {}

    class FakeResponse:
        status_code = 200

    def fake_post(url, content, headers, timeout):
        captured["url"] = url
        captured["content"] = content
        captured["headers"] = headers
        return FakeResponse()

    monkeypatch.setattr(audit_sink.httpx, "post", fake_post)
    payload = {"id": "evt-1", "event_type": "BYPASS_CREATED"}
    assert audit_sink.deliver(payload) is True
    assert captured["url"] == "https://siem.example.com/ingest"
    body = captured["content"]
    expected_signature = hmac.new(
        b"a-shared-secret-for-hmac-signing", body.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert captured["headers"]["X-SGP-Signature"] == expected_signature
    assert json.loads(body)["id"] == "evt-1"


def test_deliver_retries_then_gives_up_on_persistent_failure(monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "https://siem.example.com/ingest")
    monkeypatch.setenv("AUDIT_WEBHOOK_MAX_RETRIES", "3")
    from app.core.config import get_settings
    get_settings.cache_clear()

    attempts = {"count": 0}

    def failing_post(url, content, headers, timeout):
        attempts["count"] += 1
        raise audit_sink.httpx.ConnectError("connection refused")

    monkeypatch.setattr(audit_sink.httpx, "post", failing_post)
    monkeypatch.setattr(audit_sink.time, "sleep", lambda seconds: None)
    assert audit_sink.deliver({"id": "evt-2"}) is False
    assert attempts["count"] == 3


def test_deliver_succeeds_after_a_transient_failure(monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "https://siem.example.com/ingest")
    monkeypatch.setenv("AUDIT_WEBHOOK_MAX_RETRIES", "3")
    from app.core.config import get_settings
    get_settings.cache_clear()

    attempts = {"count": 0}

    class FakeResponse:
        status_code = 200

    def flaky_post(url, content, headers, timeout):
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise audit_sink.httpx.ConnectError("connection refused")
        return FakeResponse()

    monkeypatch.setattr(audit_sink.httpx, "post", flaky_post)
    monkeypatch.setattr(audit_sink.time, "sleep", lambda seconds: None)
    assert audit_sink.deliver({"id": "evt-3"}) is True
    assert attempts["count"] == 2


def test_deliver_rejects_non_2xx_and_retries(monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "https://siem.example.com/ingest")
    monkeypatch.setenv("AUDIT_WEBHOOK_MAX_RETRIES", "2")
    from app.core.config import get_settings
    get_settings.cache_clear()

    class FakeResponse:
        status_code = 500

    monkeypatch.setattr(audit_sink.httpx, "post", lambda url, content, headers, timeout: FakeResponse())
    monkeypatch.setattr(audit_sink.time, "sleep", lambda seconds: None)
    assert audit_sink.deliver({"id": "evt-4"}) is False


def test_submit_delivery_is_noop_without_webhook_configured(monkeypatch):
    monkeypatch.delenv("AUDIT_WEBHOOK_URL", raising=False)
    from app.core.config import get_settings
    get_settings.cache_clear()
    called = {"value": False}
    monkeypatch.setattr(audit_sink, "deliver", lambda payload: called.__setitem__("value", True))
    audit_sink.submit_delivery({"id": "evt-5"})
    assert called["value"] is False


def test_submit_delivery_runs_synchronously_when_configured(monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "https://siem.example.com/ingest")
    monkeypatch.setenv("AUDIT_WEBHOOK_DELIVER_SYNCHRONOUSLY", "true")
    from app.core.config import get_settings
    get_settings.cache_clear()
    called = {"value": False}
    monkeypatch.setattr(audit_sink, "deliver", lambda payload: called.__setitem__("value", True))
    audit_sink.submit_delivery({"id": "evt-6"})
    assert called["value"] is True
