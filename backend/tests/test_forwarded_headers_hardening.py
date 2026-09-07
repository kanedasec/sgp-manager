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
