def test_api_responses_get_a_restrictive_csp_not_the_docs_policy(client, admin_headers):
    response = client.get("/api/v1/admin/applications", headers=admin_headers)
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "unsafe-inline" not in csp
    assert "cdn.jsdelivr.net" not in csp
    assert "script-src 'none'" in csp


def test_login_response_gets_a_restrictive_csp(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    csp = response.headers["content-security-policy"]
    assert "unsafe-inline" not in csp
    assert "cdn.jsdelivr.net" not in csp


def test_docs_page_still_gets_the_permissive_csp_it_needs(client, admin_headers):
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    cookie = login.headers["set-cookie"]
    client.cookies.set(cookie.split("=", 1)[0], cookie.split("=", 1)[1].split(";", 1)[0])
    docs = client.get("/docs")
    assert docs.status_code == 200
    csp = docs.headers["content-security-policy"]
    assert "unsafe-inline" in csp
    assert "cdn.jsdelivr.net" in csp
