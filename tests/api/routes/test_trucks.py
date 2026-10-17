

# tests/api/routes/test_trucks.py

import base64
import uuid
from datetime import datetime, timezone

from tests._helpers import make_actor

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
PNG_B64 = base64.b64encode(PNG).decode()


def payload(**over):
    base = {"id": str(uuid.uuid4()), "plate_number": "abc-123 xy",
            "driver_name": "Musa Ibrahim", "driver_phone": "08030000000",
            "company": "Haulage Ltd"}
    return {**base, **over}


def sign_in(client, who, **over):
    return client.post("/api/trucks/entries", json=payload(**over), headers=who.headers)


def sign_out(client, who, entry_id, body=None):
    return client.post(f"/api/trucks/entries/{entry_id}/sign-out",
                       json=body or {}, headers=who.headers)


def lookup(client, who, plate="ABC-123 xy"):
    return client.get("/api/trucks/lookup", params={"plate": plate}, headers=who.headers)


def as_utc(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# ---- sign-in ----

def test_sign_in_creates_entry(client, officer_a):
    r = sign_in(client, officer_a)
    assert r.status_code == 201, r.text
    e = r.json()
    assert e["plate_number"] == "ABC123XY"
    assert e["facility_code"] == "CNG-A"
    assert e["signed_in_by"] == str(officer_a.id)
    assert e["signed_in_by_name"] == "Test OFF-001"
    assert e["signed_out_at"] is None and e["has_signature"] is False


def test_sign_in_ignores_facility_id_in_body(client, officer_a):
    r = sign_in(client, officer_a, facility_id=str(uuid.uuid4()))
    assert r.status_code == 201 and r.json()["facility_code"] == "CNG-A"


def test_sign_in_is_idempotent(client, officer_a):
    body = payload()
    first = client.post("/api/trucks/entries", json=body,
                        headers=officer_a.headers)
    again = client.post("/api/trucks/entries", json=body,
                        headers=officer_a.headers)
    assert first.status_code == 201 and again.status_code == 200
    assert again.json()["id"] == first.json()["id"]
    rows = client.get("/api/trucks/entries", headers=officer_a.headers).json()
    assert len(rows) == 1


def test_entry_id_cannot_be_reused_across_facilities(client, officer_a, officer_b):
    body = payload()
    assert client.post("/api/trucks/entries", json=body,
                       headers=officer_a.headers).status_code == 201
    r = client.post("/api/trucks/entries", json=body,
                    headers=officer_b.headers)
    assert r.status_code == 409


def test_client_timestamp_is_kept(client, officer_a):
    r = sign_in(client, officer_a, signed_in_at="2026-10-17T08:00:00+00:00")
    assert as_utc(r.json()["signed_in_at"]) == datetime(
        2026, 10, 17, 8, tzinfo=timezone.utc)


def test_naive_timestamp_rejected(client, officer_a):
    assert sign_in(client, officer_a,
                   signed_in_at="2026-10-17T08:00:00").status_code == 422


def test_validation(client, officer_a):
    assert sign_in(client, officer_a, plate_number="!").status_code == 422
    assert sign_in(client, officer_a, driver_name="x").status_code == 422
    assert sign_in(client, officer_a, scm_purchased="-1").status_code == 422


def test_same_plate_in_two_facilities_is_independent(client, officer_a, officer_b):
    assert sign_in(client, officer_a).status_code == 201
    assert sign_in(client, officer_b).status_code == 201


# ---- already inside / returning trucks ----

def test_cannot_sign_in_a_truck_that_is_inside(client, officer_a):
    first = sign_in(client, officer_a).json()
    r = sign_in(client, officer_a, plate_number="ABC123XY")
    assert r.status_code == 409 and r.json(
    )["detail"]["code"] == "truck_already_inside"
    assert sign_out(client, officer_a, first["id"]).status_code == 200
    assert sign_in(client, officer_a).status_code == 201


def test_lookup_lifecycle(client, officer_a):
    assert lookup(client, officer_a).json() is None
    e = sign_in(client, officer_a).json()
    found = lookup(client, officer_a, "ABC-123 xy").json()
    assert found["plate_number"] == "ABC123XY"
    assert found["driver_name"] == "Musa Ibrahim"
    assert found["open_entry_id"] == e["id"]
    sign_out(client, officer_a, e["id"])
    assert lookup(client, officer_a).json()["open_entry_id"] is None


def test_returning_truck_updates_registry_but_not_history(client, officer_a):
    first = sign_in(client, officer_a, driver_name="Old Driver").json()
    sign_out(client, officer_a, first["id"])
    assert sign_in(client, officer_a,
                   driver_name="New Driver").status_code == 201
    assert lookup(client, officer_a).json()["driver_name"] == "New Driver"
    rows = client.get("/api/trucks/entries", headers=officer_a.headers).json()
    assert {r["driver_name"] for r in rows} == {"Old Driver", "New Driver"}


# ---- sign-out ----

def test_sign_out_flow_and_idempotency(client, officer_a):
    e = sign_in(client, officer_a).json()
    r = sign_out(client, officer_a, e["id"], {
        "signed_out_at": "2026-10-17T10:00:00+00:00", "scm_purchased": "12.50"})
    assert r.status_code == 200
    j = r.json()
    assert j["signed_out_by"] == str(officer_a.id)
    assert float(j["scm_purchased"]) == 12.5
    again = sign_out(client, officer_a, e["id"], {"scm_purchased": "99"})
    assert again.status_code == 200
    # first sign-out wins
    assert again.json()["signed_out_at"] == j["signed_out_at"]
    assert float(again.json()["scm_purchased"]) == 12.5


def test_sign_out_errors(client, officer_a, officer_b):
    e = sign_in(client, officer_a).json()
    assert sign_out(client, officer_a, str(uuid.uuid4())).status_code == 404
    # other facility
    assert sign_out(client, officer_b, e["id"]).status_code == 404
    assert sign_out(client, officer_a, e["id"], {
                    "scm_purchased": "-1"}).status_code == 422


# ---- signatures ----

def test_signature_round_trip_and_scoping(client, officer_a, officer_b, cso):
    r = sign_in(client, officer_a,
                signature="data:image/png;base64," + PNG_B64)
    assert r.status_code == 201 and r.json()["has_signature"] is True
    eid = r.json()["id"]
    got = client.get(
        f"/api/trucks/entries/{eid}/signature", headers=officer_a.headers)
    assert got.status_code == 200
    assert got.headers["content-type"] == "image/png" and got.content == PNG
    assert client.get(f"/api/trucks/entries/{eid}/signature",
                      headers=cso.headers).status_code == 200
    assert client.get(f"/api/trucks/entries/{eid}/signature",
                      headers=officer_b.headers).status_code == 404


def test_missing_signature_is_404(client, officer_a):
    eid = sign_in(client, officer_a).json()["id"]
    assert client.get(f"/api/trucks/entries/{eid}/signature",
                      headers=officer_a.headers).status_code == 404


def test_bad_signatures_rejected(client, officer_a):
    for bad in ("%%%not-base64%%%",
                base64.b64encode(b"not a png").decode(),
                base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * (201 * 1024)).decode()):
        r = sign_in(client, officer_a, signature=bad)
        assert r.status_code == 422, bad[:20]
        assert r.json()["detail"]["code"] == "invalid_signature"
    assert client.get("/api/trucks/entries",
                      headers=officer_a.headers).json() == []


# ---- permissions ----

def test_only_facility_officers_write(client, officer_a, manager_a, cso, admin):
    assert client.post("/api/trucks/entries",
                       json=payload()).status_code == 401
    for who in (manager_a, cso, admin):
        assert sign_in(client, who).status_code == 403
        assert lookup(client, who).status_code == 403
        assert sign_out(client, who, str(uuid.uuid4())).status_code == 403


def test_temp_pin_blocks_trucks(client):
    a = make_actor(client, code="OFF-009",
                   facility="CNG-A", must_change_pin=True)
    r = lookup(client, a, "X1")
    assert r.status_code == 403 and r.json(
    )["detail"]["code"] == "must_change_pin"


# ---- reads / scoping ----

def plates(client, who, **params):
    r = client.get("/api/trucks/entries", params=params, headers=who.headers)
    assert r.status_code == 200, r.text
    return {e["plate_number"] for e in r.json()}


def test_read_scoping(client, officer_a, officer_b, manager_a, cso, admin):
    sign_in(client, officer_a, plate_number="AAA111")
    sign_in(client, officer_b, plate_number="BBB222")
    assert plates(client, officer_a) == {"AAA111"}
    assert plates(client, officer_b) == {"BBB222"}
    assert plates(client, manager_a) == {"AAA111"}
    assert plates(client, cso) == {"AAA111", "BBB222"}
    assert plates(client, admin) == {"AAA111", "BBB222"}
    # facility_code is a filter for global viewers, never a way out of your scope
    assert plates(client, officer_a, facility_code="CNG-B") == {"AAA111"}
    assert plates(client, cso, facility_code="cng-b") == {"BBB222"}


def test_filters_and_pagination(client, officer_a):
    ids = {}
    for p in ("AAA111", "AAB222", "CCC333"):
        ids[p] = sign_in(client, officer_a, plate_number=p).json()["id"]
    sign_out(client, officer_a, ids["AAA111"])
    assert plates(client, officer_a, open="true") == {"AAB222", "CCC333"}
    assert plates(client, officer_a, plate="aa") == {"AAA111", "AAB222"}
    assert len(client.get("/api/trucks/entries", params={"limit": 2},
                          headers=officer_a.headers).json()) == 2
    assert len(client.get("/api/trucks/entries", params={"limit": 2, "offset": 2},
                          headers=officer_a.headers).json()) == 1
    assert client.get("/api/trucks/entries", params={"limit": 0},
                      headers=officer_a.headers).status_code == 422


def test_date_filters(client, officer_a):
    sign_in(client, officer_a, plate_number="OLD111",
            signed_in_at="2026-01-01T08:00:00+00:00")
    sign_in(client, officer_a, plate_number="NEW222",
            signed_in_at="2026-10-01T08:00:00+00:00")
    assert plates(client, officer_a,
                  date_from="2026-06-01T00:00:00+00:00") == {"NEW222"}
    assert plates(client, officer_a,
                  date_to="2026-06-01T00:00:00+00:00") == {"OLD111"}
