"""HTTP-layer self-check: signed intents and the operator boundary.

Every other suite calls main.decide() directly, so verify_intent(), operator_only()
and _public() had zero coverage. Mutation testing found five defects that survived the
whole suite because of it: hmac.compare_digest replaced with ==, the nonce insert
removed, the skew window widened to ten years, operator_only stripped from /approve,
and payout_fp leaking out of _public.

Run: python test_http.py
"""
import hashlib
import hmac
import json
import tempfile
import time
import uuid
from pathlib import Path

import main

main.DB_PATH = Path(tempfile.mkdtemp()) / "test_firewall.db"
main.init_db()

from fastapi.testclient import TestClient  # noqa: E402  (must follow the DB_PATH swap)

client = TestClient(main.app)
AGENT, SECRET = "ops-agent", "key-ops-123"
INTENT = dict(merchant_id="acme-supplies", currency="INR", payout_account="ACME-ACC-001")


def signed(intent, secret=SECRET, agent=AGENT, ts=None, nonce=None, send_body=None):
    """Sign one intent. `send_body` lets a caller sign one payload and send another."""
    body = json.dumps(intent).encode()
    ts = ts or str(int(time.time()))
    nonce = nonce or str(uuid.uuid4())
    mac = hmac.new(secret.encode(),
                   main.signing_input(agent, ts, nonce, body), hashlib.sha256).hexdigest()
    return client.post("/pay", content=send_body if send_body is not None else body,
                       headers={"Content-Type": "application/json", "X-Agent-Id": agent,
                                "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": mac})


def intent(ref, amount=10000, **over):
    return {**INTENT, **over, "invoice_ref": ref, "amount": amount}


# --- a correctly signed intent is the only thing that moves money -------------
r = signed(intent("HTTP-1"))
assert r.status_code == 200, r.text
assert r.json()["decision"] == "settled", r.text

# --- a bearer key is not a signature -----------------------------------------
assert client.post("/pay", json=intent("HTTP-2"),
                   headers={"X-API-Key": SECRET}).status_code == 422

# --- wrong secret --------------------------------------------------------------
r = signed(intent("HTTP-3"), secret="not-the-secret")
assert r.status_code == 401 and "signature" in r.json()["detail"], r.text

# --- the signature is bound to THIS body: edit the amount in flight -----------
r = signed(intent("HTTP-4", 10000),
           send_body=json.dumps(intent("HTTP-4", 9_900_000)).encode())
assert r.status_code == 401 and "signature" in r.json()["detail"], r.text

# --- one agent cannot present another agent's signature ----------------------
body = json.dumps(intent("HTTP-5")).encode()
ts, nonce = str(int(time.time())), str(uuid.uuid4())
mac = hmac.new(SECRET.encode(), main.signing_input(AGENT, ts, nonce, body),
               hashlib.sha256).hexdigest()
r = client.post("/pay", content=body,
                headers={"Content-Type": "application/json", "X-Agent-Id": "race-agent",
                         "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": mac})
assert r.status_code == 401, r.text

# --- the skew window is real, in both directions ------------------------------
now = int(time.time())
assert signed(intent("HTTP-6"), ts=str(now - 3600)).status_code == 401
assert signed(intent("HTTP-7"), ts=str(now + 3600)).status_code == 401
assert signed(intent("HTTP-8"), ts=str(now - main.INTENT_SKEW_SECONDS + 5)).status_code == 200

# --- replay: the same nonce cannot be spent twice -----------------------------
reused = str(uuid.uuid4())
assert signed(intent("HTTP-9"), nonce=reused).status_code == 200
r = signed(intent("HTTP-10"), nonce=reused)
assert r.status_code == 401 and "nonce" in r.json()["detail"], r.text

# --- a revoked agent is refused even with a valid signature -------------------
conn = main.db()
rogue = conn.execute("SELECT id, api_key FROM agents WHERE status!='active'").fetchone()
conn.close()
if rogue:
    r = signed(intent("HTTP-11"), secret=rogue["api_key"], agent=rogue["id"])
    assert r.status_code == 401, r.text

# --- StrictInt: a bool or a string is not an amount ---------------------------
for bad in (True, "5000", 1.5):
    r = signed(intent("HTTP-BAD", bad))
    assert r.status_code == 400, (bad, r.status_code, r.text)


# --- the operator boundary ----------------------------------------------------
# TestClient reports client.host == "testclient", so every operator endpoint must
# refuse it. This is the assertion that catches operator_only being removed.
assert client.get("/demo/keys").status_code == 403
assert client.post("/demo/reset").status_code == 403
assert client.post("/demo/mcp/0").status_code == 403
assert client.post("/reconcile").status_code == 403
assert client.post("/rails/card_rail/status", json={"status": "down"}).status_code == 403
assert client.post("/approvals/does-not-matter/approve",
                   json={"actor": "attacker", "reason": "lgtm"}).status_code == 403
assert client.post("/approvals/does-not-matter/deny",
                   json={"actor": "attacker", "reason": "no"}).status_code == 403

# --- read models must not leak the payout fingerprint -------------------------
listed = client.get("/payments").json()
assert listed, "expected at least one payment"
for row in listed:
    assert "payout_fp" not in row, row
one = client.get(f"/payments/{listed[0]['id']}").json()
assert "payout_fp" not in one, one
for row in client.get("/approvals").json():
    assert "payout_fp" not in row, row
for step in client.get(f"/replay/{listed[0]['id']}").json()["steps"]:
    assert "payout_fp" not in str(step), step
for row in client.get("/agents").json():
    assert "api_key" not in row, row

# --- limits are clamped, not honoured verbatim --------------------------------
assert len(client.get("/payments?limit=1000000").json()) <= 500
assert len(client.get("/audit?limit=1000000").json()) <= 1000

print("HTTP: all checks passed")
