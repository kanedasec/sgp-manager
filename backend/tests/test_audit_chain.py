from app.core.database import SessionLocal
from app.models import AuditLog
from app.services.audit_chain import ChainVerificationError, GENESIS_HASH, verify_chain


def test_admin_actions_produce_a_hashed_chained_audit_trail(client, admin_headers, owner):
    with SessionLocal() as db:
        rows = db.query(AuditLog).order_by(AuditLog.sequence.asc()).all()
    assert len(rows) >= 1
    assert rows[0].sequence == 1
    assert rows[0].prev_hash == GENESIS_HASH
    assert rows[0].entry_hash is not None
    for previous, current in zip(rows, rows[1:]):
        assert current.sequence == previous.sequence + 1
        assert current.prev_hash == previous.entry_hash


def test_verify_chain_endpoint_reports_intact_after_normal_activity(client, admin_headers, owner):
    response = client.get("/api/v1/admin/audit-logs/verify-chain", headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is True
    assert body["verified_entries"] >= 1


def test_verify_chain_endpoint_requires_admin(client, admin_headers):
    create = client.post(
        "/api/v1/admin/users", headers=admin_headers,
        json={
            "username": "auditor", "password": "AnotherStrongPass!456", "display_name": "Auditor",
            "email": "auditor@example.com", "role": "USER", "group_ids": [],
        },
    )
    login = client.post("/api/v1/auth/login", json={"username": "auditor", "password": "AnotherStrongPass!456"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    response = client.get("/api/v1/admin/audit-logs/verify-chain", headers=headers)
    assert response.status_code == 403


def test_verify_chain_detects_a_tampered_row(client, admin_headers, owner):
    with SessionLocal() as db:
        row = db.query(AuditLog).filter(AuditLog.entry_hash.is_not(None)).order_by(AuditLog.sequence.asc()).first()
        row.event_metadata = {**(row.event_metadata or {}), "tampered": True}
        db.commit()

    with SessionLocal() as db:
        try:
            verify_chain(db)
            assert False, "expected ChainVerificationError"
        except ChainVerificationError as exc:
            assert exc.sequence == row.sequence

    response = client.get("/api/v1/admin/audit-logs/verify-chain", headers=admin_headers)
    body = response.json()
    assert body["intact"] is False
    assert body["broken_at_sequence"] == row.sequence


def test_verify_chain_detects_a_deleted_row(client, admin_headers, owner):
    with SessionLocal() as db:
        rows = db.query(AuditLog).filter(AuditLog.entry_hash.is_not(None)).order_by(AuditLog.sequence.asc()).all()
        assert len(rows) >= 2
        db.delete(rows[0])
        db.commit()

    response = client.get("/api/v1/admin/audit-logs/verify-chain", headers=admin_headers)
    body = response.json()
    assert body["intact"] is False


def test_multiple_audits_in_one_request_chain_correctly(client, admin_headers):
    # create_user in one request records exactly one audit event, but the
    # owner fixture chains several requests together; this test specifically
    # exercises consecutive record_audit() calls sharing one uncommitted
    # session by hitting an endpoint that itself commits, then immediately
    # another, and asserting the resulting sequence has no gaps or forks.
    for index in range(3):
        response = client.post(
            "/api/v1/admin/owners", headers=admin_headers,
            json={"name": f"Team {index}", "slug": f"team-{index}", "description": "x"},
        )
        assert response.status_code == 201

    with SessionLocal() as db:
        rows = db.query(AuditLog).order_by(AuditLog.sequence.asc()).all()
    sequences = [row.sequence for row in rows]
    assert sequences == list(range(1, len(rows) + 1))
    for previous, current in zip(rows, rows[1:]):
        assert current.prev_hash == previous.entry_hash
