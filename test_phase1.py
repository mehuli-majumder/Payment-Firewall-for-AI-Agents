"""Phase 1 self-check. Run: python test_phase1.py"""
import tempfile
import threading
from pathlib import Path

import main

main.DB_PATH = Path(tempfile.mkdtemp()) / "test_firewall.db"
main.init_db()

# Probation (Rs.500 until an agent has RISK_MIN_HISTORY settlements) is on by default
# and is covered by test_phase4.py. This suite moves larger amounts to test something
# else, so it opts out rather than warming up before every assertion.
main.PROBATION_CAP = 0


# The model is not the subject of this suite. These agents currently stay below
# RISK_MIN_HISTORY by accident, so one extra settling payment would silently introduce a
# live Ollama call. Pin it closed.
def _no_model(_signals):
    raise AssertionError("risk_review must not be reached in this suite")


main.risk_review = _no_model


OPS = "key-ops-123"
ACME = dict(merchant_id="acme-supplies", currency="INR", payout_account="ACME-ACC-001")


def pay(key=OPS, invoice="inv-1", amount=100000, **over):
    kw = {**ACME, **over}
    return main.decide(key, kw["merchant_id"], invoice, amount, kw["currency"], kw["payout_account"])


# clean payment settles
r = pay(invoice="inv-clean", amount=100000)
assert r["decision"] == "settled", r

# duplicate, same amount -> replayed, not paid twice
r2 = pay(invoice="inv-clean", amount=100000)
assert r2["decision"] == "replayed" and r2["payment_id"] == r["payment_id"], r2

# duplicate, different amount -> blocked for review
r3 = pay(invoice="inv-clean", amount=100100)
assert r3["decision"] == "blocked" and "DIFFERENT amount" in r3["reason"], r3

# budget reflects exactly one settlement
b = main.budget("ops-agent")
assert b["spent"] == 100000 and b["reserved"] == 0, b

# validation: negative / zero / non-int amounts rejected
for bad in (-5, 0, True, "100"):
    assert pay(invoice="inv-bad", amount=bad)["decision"] == "rejected", bad

# revoked key rejected
assert pay(key="key-rogue-789", invoice="inv-rogue")["decision"] == "rejected"

# unknown merchant blocked
assert pay(invoice="inv-x", merchant_id="shady-corp")["decision"] == "blocked"

# currency mismatch blocked
assert "currency mismatch" in pay(invoice="inv-fx", currency="USD")["reason"]

# single-transaction cap (ops cap = 150000)
assert "single-transaction cap" in pay(invoice="inv-big", amount=200000)["reason"]

# changed payout account on whitelisted merchant -> escalated, budget held
r = pay(invoice="inv-fraud", amount=50000, payout_account="ATTACKER-ACC-666")
assert r["decision"] == "pending" and r["state"] == "PENDING_APPROVAL", r
assert main.budget("ops-agent")["reserved"] == 50000

# split-payment / velocity: 100k settled + 50k pending = 150k in the last hour (cap 150000);
# one more sub-cap payment must trip the velocity rule even though it passes alone
r = pay(invoice="inv-split", amount=10000)
assert r["decision"] == "blocked" and "velocity" in r["reason"], r

# concurrent budget race: two 300k payments, 500k daily cap -> exactly one settles
results = []
threads = [
    threading.Thread(target=lambda i=i: results.append(
        pay(key="key-race-456", invoice=f"inv-race-{i}", amount=300000)))
    for i in range(2)
]
[t.start() for t in threads]
[t.join() for t in threads]
outcomes = sorted(r["decision"] for r in results)
assert outcomes == ["blocked", "settled"], results
assert main.budget("race-agent")["spent"] == 300000

# rate limit: a key whose every request is refused still writes an audit row per attempt,
# so the limiter has to cut in before the pipeline touches the database at all
main.RATE_LIMIT = 5
main._RATE.clear()
for i in range(5):
    assert main.decide("key-nonsense", "acme-supplies", f"inv-rl-{i}", 1000, "INR", "ACME-ACC-001"
                       )["decision"] == "rejected"
limited = main.decide("key-nonsense", "acme-supplies", "inv-rl-x", 1000, "INR", "ACME-ACC-001")
assert limited["decision"] == "rate_limited" and limited["payment_id"] is None, limited
main.RATE_LIMIT = 60
main._RATE.clear()

print("Phase 1: all checks passed")
