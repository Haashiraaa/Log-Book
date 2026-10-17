

# tests/api/routes/test_auth.py

import pytest

from backend.src.config.settings import Settings
from tests._helpers import PIN, login, login_response


def me(client, headers):
    return client.get("/api/auth/me", headers=headers)


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_login_ok_and_case_insensitive(client, officer_a):
    r = login_response(client, "off-001", "cng-a")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["officer"]["officer_code"] == "OFF-001"
    assert body["officer"]["facility_code"] == "CNG-A"
    assert body["officer"]["role"] == "officer"


def test_login_failures_look_identical(client, officer_a):
    for code, fac, pin in [("OFF-001", "CNG-A", "000111"),   # wrong PIN
                           ("OFF-001", "CNG-B", PIN),        # wrong facility
                           # global login for a facility officer
                           ("OFF-001", None, PIN),
                           ("OFF-999", "CNG-A", PIN)]:       # unknown officer
        r = login_response(client, code, fac, pin)
        assert r.status_code == 401
        assert r.json()["detail"]["code"] == "invalid_credentials"


def test_lockout(client, officer_a):
    for _ in range(Settings.MAX_PIN_ATTEMPTS - 1):
        assert login_response(client, "OFF-001", "CNG-A",
                              "000111").status_code == 401
    r = login_response(client, "OFF-001", "CNG-A", "000111")
    assert r.status_code == 429
    assert r.json()["detail"]["code"] == "account_locked"
    assert int(r.headers["retry-after"]) > 0
    assert login_response(client, "OFF-001", "CNG-A", PIN).status_code == 429


def test_me_requires_valid_token(client, officer_a):
    assert me(client, officer_a.headers).status_code == 200
    r = client.get("/api/auth/me")
    assert r.status_code == 401 and r.json(
    )["detail"]["code"] == "invalid_token"
    r = me(client, {"Authorization": "Bearer garbage"})
    assert r.status_code == 401 and r.json(
    )["detail"]["code"] == "invalid_token"


def test_refresh(client, officer_a):
    body = login_response(client, "OFF-001", "CNG-A").json()
    r = client.post("/api/auth/refresh",
                    json={"refresh_token": body["refresh_token"]})
    assert r.status_code == 200
    new = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert me(client, new).status_code == 200
    r = client.post("/api/auth/refresh", json={"refresh_token": "x" * 40})
    assert r.status_code == 401


def test_logout_revokes_everything_and_is_idempotent(client, officer_a):
    body = login_response(client, "OFF-001", "CNG-A").json()
    headers = {"Authorization": f"Bearer {body['access_token']}"}
    rt = {"refresh_token": body["refresh_token"]}
    assert client.post("/api/auth/logout", json=rt).status_code == 204
    assert client.post("/api/auth/logout", json=rt).status_code == 204
    r = client.post("/api/auth/refresh", json=rt)
    assert r.status_code == 401 and r.json(
    )["detail"]["code"] == "session_revoked"
    r = me(client, headers)
    assert r.status_code == 401 and r.json(
    )["detail"]["code"] == "session_revoked"


@pytest.mark.parametrize("bad", ["123456", "111111", "12ab56", "123"])
def test_change_pin_policy(client, officer_a, bad):
    r = client.post("/api/auth/change-pin", headers=officer_a.headers,
                    json={"current_pin": PIN, "new_pin": bad})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "weak_pin"


def test_change_pin_wrong_current_and_same_pin(client, officer_a):
    r = client.post("/api/auth/change-pin", headers=officer_a.headers,
                    json={"current_pin": "000111", "new_pin": "739150"})
    assert r.status_code == 401 and r.json(
    )["detail"]["code"] == "invalid_credentials"
    r = client.post("/api/auth/change-pin", headers=officer_a.headers,
                    json={"current_pin": PIN, "new_pin": PIN})
    assert r.status_code == 422


def test_change_pin_signs_out_other_phones(client, officer_a):
    h1 = login(client, "OFF-001", "CNG-A")
    h2 = login(client, "OFF-001", "CNG-A")
    r = client.post("/api/auth/change-pin", headers=h1,
                    json={"current_pin": PIN, "new_pin": "739150"})
    assert r.status_code == 204
    assert me(client, h1).status_code == 200
    r = me(client, h2)
    assert r.status_code == 401 and r.json(
    )["detail"]["code"] == "session_revoked"
    assert login_response(client, "OFF-001", "CNG-A", PIN).status_code == 401
    assert login_response(client, "OFF-001", "CNG-A",
                          "739150").status_code == 200
