

# tests/api/routes/test_super_admin.py

import pytest

from tests._helpers import login, login_response

BASE = "/api/super-admin/admins"


def test_only_super_admin_gets_in(client, admin, officer_a):
    assert client.get(BASE).status_code == 401
    for who in (admin, officer_a):
        r = client.get(BASE, headers=who.headers)
        assert r.status_code == 403


def test_create_global_admin(client, super_admin):
    r = client.post(BASE, headers=super_admin.headers,
                    json={"full_name": "New Admin", "role": "cso"})
    assert r.status_code == 201, r.text
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["officer"]["officer_code"] == "CSO-001"
    assert body["officer"]["is_admin"] is True
    assert body["officer"]["is_super_admin"] is False
    h = login(client, "CSO-001", None, body["temp_pin"])
    assert client.get(
        "/api/auth/me", headers=h).json()["must_change_pin"] is True


def test_create_facility_admin(client, super_admin):
    # a super admin is also an admin, so it can create the facility itself
    assert client.post("/api/admin/facilities", headers=super_admin.headers,
                       json={"code": "CNG-S", "name": "Station S"}).status_code == 201
    r = client.post(BASE, headers=super_admin.headers,
                    json={"full_name": "Site Manager", "role": "facility_manager",
                          "facility_code": "CNG-S"})
    assert r.status_code == 201, r.text
    assert r.json()["officer"]["officer_code"] == "MGR-001"
    assert r.json()["officer"]["facility_code"] == "CNG-S"


def test_create_admin_validation(client, super_admin):
    r = client.post(BASE, headers=super_admin.headers,
                    json={"full_name": "No Facility", "role": "facility_manager"})
    assert r.status_code == 422
    r = client.post(BASE, headers=super_admin.headers,
                    json={"full_name": "Global With Fac", "role": "cso",
                          "facility_code": "CNG-A"})
    assert r.status_code == 422


def test_list_admins(client, super_admin, admin, officer_a):
    rows = client.get(BASE, headers=super_admin.headers).json()
    assert {o["officer_code"] for o in rows} == {"SA-01", "ADM-001"}


def test_grant_then_revoke_admin(client, super_admin, officer_a):
    r = client.post(f"{BASE}/{officer_a.id}/grant",
                    headers=super_admin.headers)
    assert r.status_code == 200 and r.json()["is_admin"] is True
    assert client.get("/api/admin/facilities",
                      headers=officer_a.headers).status_code == 200

    r = client.post(f"{BASE}/{officer_a.id}/revoke",
                    headers=super_admin.headers)
    assert r.status_code == 200 and r.json()["is_admin"] is False
    assert client.get("/api/admin/facilities",
                      headers=officer_a.headers).status_code == 403
    assert login_response(
        client, "OFF-001", "CNG-A").status_code == 200  # login unaffected


def test_cannot_grant_to_disabled_account(client, super_admin, admin, officer_a):
    client.post(
        f"/api/admin/officers/{officer_a.id}/disable", headers=admin.headers)
    r = client.post(f"{BASE}/{officer_a.id}/grant",
                    headers=super_admin.headers)
    assert r.status_code == 409


def test_disable_enable_reset_admin(client, super_admin, admin):
    r = client.post(f"{BASE}/{admin.id}/reset-pin",
                    headers=super_admin.headers)
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert len(r.json()["temp_pin"]) == 6
    assert client.post(f"{BASE}/{admin.id}/disable",
                       headers=super_admin.headers).json()["is_active"] is False
    assert login_response(client, "ADM-001").status_code == 401
    assert client.post(f"{BASE}/{admin.id}/enable",
                       headers=super_admin.headers).json()["is_active"] is True


@pytest.mark.parametrize("action", ["grant", "revoke", "disable", "enable", "reset-pin"])
def test_super_admin_is_untouchable_via_api(client, super_admin, action):
    r = client.post(f"{BASE}/{super_admin.id}/{action}",
                    headers=super_admin.headers)
    assert r.status_code == 404


def test_wrong_admin_state_is_404(client, super_admin, admin, officer_a):
    assert client.post(f"{BASE}/{admin.id}/grant",
                       headers=super_admin.headers).status_code == 404   # already admin
    assert client.post(f"{BASE}/{officer_a.id}/revoke",
                       headers=super_admin.headers).status_code == 404   # not an admin
