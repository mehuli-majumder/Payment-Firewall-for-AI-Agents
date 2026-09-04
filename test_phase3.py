"""Phase 3 self-check: hash-chained audit log + replay. Run: python test_phase3.py"""
import tempfile
import time
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


def pay(invoice, amount=100000, merchant="acme-supplies", account="ACME-ACC-001", key=OPS):
    return main.decide(key, merchant, invoice, amount, "INR", account)


# every stage of a clean payment is logged, in order, and the chain verifies
r = pay("inv-clean")
rep = main.replay(r["payment_id"])
assert [s["event"] for s in rep["steps"]] == ["reserved", "risk_skipped", "executing", "settled"], rep["steps"]
assert rep["chain_intact"] is True
assert main.verify_chain()["intact"] is True

# a rejection with no payment row still gets logged (payment_id NULL)
main.decide(OPS, "acme-supplies", "inv-bad", -5, "INR", "ACME-ACC-001")
conn = main.db()
row = conn.execute(
    "SELECT * FROM audit_log WHERE payment_id IS NULL ORDER BY id DESC LIMIT 1"
).fetchone()
conn.close()
assert row["event"] == "rejected" and "positive integer" in row["detail"], dict(row)

# blocked and escalated payments each leave their own reason in the chain
blocked = pay("inv-big", amount=200000)
assert main.replay(blocked["payment_id"])["steps"][0]["event"] == "blocked"

escalated = pay("inv-fraud", amount=50000, account="ATTACKER-ACC-666")
assert main.replay(escalated["payment_id"])["steps"][-1]["event"] == "escalated"

# approve requires a reason, and both the approval and the settle land in the chain
main.resolve_approval(escalated["payment_id"], "approve", "priya", reason="verified by phone")
events = [s["event"] for s in main.replay(escalated["payment_id"])["steps"]]
assert events == ["escalated", "approved", "executing", "settled"], events
assert all(s["actor"] != "rule" for s in main.replay(escalated["payment_id"])["steps"][1:2]), "approval actor should be human:priya"

# a losing approval race is logged too, not silently dropped
# (race-agent, not ops-agent: ops-agent's 1hr velocity cap is already spent by prior asserts above)
r2 = pay("inv-fraud-2", amount=50000, account="ATTACKER-ACC-666", key="key-race-456")
pid2 = r2["payment_id"]
main.resolve_approval(pid2, "deny", "alice", reason="rejected")
conflict = main.resolve_approval(pid2, "approve", "bob", reason="too late")
assert conflict["decision"] == "conflict"
events2 = [s["event"] for s in main.replay(pid2)["steps"]]
assert events2 == ["escalated", "denied", "approve_conflict"], events2

# expiry is logged by the sweep, actor 'rule', with the TTL reason
# a different account from inv-fraud-2: that one was denied above, and a denied payout
# account is now blocked outright instead of escalating a second time
r3 = pay("inv-fraud-3", amount=50000, account="ATTACKER-ACC-777", key="key-race-456")
pid3 = r3["payment_id"]
conn = main.db()
conn.execute("UPDATE payments SET expires_at=? WHERE id=?", (int(time.time()) - 1, pid3))
conn.close()
main.budget("race-agent")  # triggers the sweep
events3 = [s["event"] for s in main.replay(pid3)["steps"]]
assert events3 == ["escalated", "expired"], events3

# tampering with a stored entry breaks verification, both globally and per-payment
conn = main.db()
conn.execute("UPDATE audit_log SET detail='forged' WHERE payment_id=? AND event='reserved'",
             (r["payment_id"],))
conn.close()
assert main.verify_chain()["intact"] is False
rep_after = main.replay(r["payment_id"])
assert rep_after["chain_intact"] is False
assert any(not s["hash_valid"] for s in rep_after["steps"])

print("Phase 3: all checks passed")
