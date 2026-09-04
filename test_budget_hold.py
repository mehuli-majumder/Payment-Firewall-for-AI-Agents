"""Budget-hold self-check: a hold ends when the payment resolves, never when the clock
runs past 24h — and the overrun counter is measured, not hardcoded.

Run: python test_budget_hold.py
"""
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

main.risk_review = lambda signals: {"decision": "allow", "cited_signals": [], "reasoning": "",
                                    "raw_llm_response": "{}", "available": True}

RACE = "key-race-456"  # daily 500000, velocity 600000, single_txn 300000


def pay(invoice, amount):
    return main.decide(RACE, "acme-supplies", invoice, amount, "INR", "ACME-ACC-001")


# a rail timeout leaves the money held: not spent, not released
r = pay("inv-timeout", main.TIMEOUT_TRIGGER)
assert r["state"] == "UNKNOWN", r
assert main.budget("race-agent")["reserved"] == main.TIMEOUT_TRIGGER

# age the hold past the 24h boundary and tighten the cap so the next payment either
# fits (hold leaked) or doesn't (hold intact)
conn = main.db()
conn.execute("UPDATE payments SET created_at=? WHERE id=?",
             (int(time.time()) - 25 * 3600, r["payment_id"]))
conn.execute("UPDATE agents SET daily_cap=400000, velocity_cap=900000 WHERE id='race-agent'")
conn.close()

b = main.budget("race-agent")
assert b["reserved"] == main.TIMEOUT_TRIGGER, b            # the clock did not release it
assert b["available"] == 400000 - main.TIMEOUT_TRIGGER, b

# 130000 held + 300000 exceeds the 400000 cap. Before the fix the aged hold dropped out
# of the sum and this settled — the ledger committing past its own cap.
r2 = pay("inv-over", 300000)
assert r2["decision"] == "blocked" and "daily budget" in r2["reason"], r2

# (release-on-resolution is already covered by test_phase5 / test_phase2)

# the dashboard's overrun counter is computed from the ledger, not a constant
assert main.get_metrics()["budget_overruns"] == 0
conn = main.db()
conn.execute("UPDATE agents SET daily_cap=100000 WHERE id='race-agent'")  # below what's committed
conn.close()
assert main.get_metrics()["budget_overruns"] == 1

print("Budget hold: all checks passed")
