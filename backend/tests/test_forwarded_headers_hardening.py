import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_dockerfile_does_not_trust_all_forwarded_ips():
    dockerfile = (REPO_ROOT / "backend" / "Dockerfile").read_text()
    assert "--forwarded-allow-ips=*" not in dockerfile
    match = re.search(r"--forwarded-allow-ips=([^\s\"]+)", dockerfile)
    assert match, "uvicorn CMD must set --forwarded-allow-ips explicitly"
    ranges = match.group(1).split(",")
    assert "*" not in ranges
    assert len(ranges) >= 1


def test_nginx_conf_overwrites_rather_than_appends_x_forwarded_for():
    nginx_conf = (REPO_ROOT / "frontend" / "nginx.conf").read_text()
    assert "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;" not in nginx_conf
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in nginx_conf


def test_nginx_conf_trusts_the_upstream_edge_proxy_via_realip_module():
    # Regression test for the fix in this PR: in the real Caddy -> nginx ->
    # backend topology, nginx's own $remote_addr is always Caddy's
    # container address (its immediate TCP peer), never the real external
    # client, unless the realip module is configured to resolve it from
    # Caddy's own X-Forwarded-For. Without this, the X-Forwarded-For
    # overwrite fix above collapses every real client IP into one fixed
    # internal address, breaking audit source_ip attribution and the
    # per-IP rate-limit bucket.
    nginx_conf = (REPO_ROOT / "frontend" / "nginx.conf").read_text()
    assert "real_ip_header X-Forwarded-For;" in nginx_conf
    assert "real_ip_recursive on;" in nginx_conf
    assert "set_real_ip_from" in nginx_conf
    # The trusted ranges must stay private/internal, not "*" or a public
    # range -- otherwise this reopens the exact spoofing hole PR #23 closed.
    for line in nginx_conf.splitlines():
        if line.strip().startswith("set_real_ip_from"):
            assert "0.0.0.0/0" not in line
