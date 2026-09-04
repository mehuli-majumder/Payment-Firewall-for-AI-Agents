"""Phase 5 self-check: router + mock rails + UNKNOWN/reconciliation. Run: python test_phase5.py"""
import tempfile
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

# race-agent has higher caps (single_txn 300000, velocity 600000) — needed because
# FAIL_TRIGGER/TIMEOUT_TRIGGER amounts exceed ops-agent's single-transaction cap.
RACE = "key-race-456"


def pay(invoice, amount, key=RACE):
    return main.decide(key, "acme-supplies", invoice, amount, "INR", "ACME-ACC-001")


# --- clean payment: router picks the cheapest rail (x402_rail, 80bps) and it settles ---
r = pay("inv-clean", 10000)
assert r["decision"] == "settled" and r["rail"] == "x402_rail", r
row = main.db().execute("SELECT rail FROM payments WHERE id=?", (r["payment_id"],)).fetchone()
assert row["rail"] == "x402_rail", dict(row)

# --- deterministic failure trigger: any exact multiple of the FAIL_TRIGGER amount is rejected ---
r_fail = pay("inv-declined", main.FAIL_TRIGGER)
assert r_fail["decision"] == "failed" and r_fail["state"] == "FAILED", r_fail
assert main.budget("race-agent")["reserved"] == 0  # FAILED releases the reservation, doesn't leak it

# --- deterministic timeout trigger on x402_rail: money is held as UNKNOWN, not lost, not spent ---
# (checked via a raw row read, not budget() — budget() itself reconciles eagerly, see below)
r_timeout = pay("inv-timeout", main.TIMEOUT_TRIGGER)
assert r_timeout["decision"] == "reconciling" and r_timeout["state"] == "UNKNOWN", r_timeout
row = main.db().execute("SELECT state FROM payments WHERE id=?", (r_timeout["payment_id"],)).fetchone()
assert row["state"] == "UNKNOWN", dict(row)
events = [s["event"] for s in main.replay(r_timeout["payment_id"])["steps"]]
assert events[-1] == "unknown", events

# the first ask gets "pending": the rail hasn't confirmed anything, so the payment stays
# UNKNOWN and the money stays held — the system sits in not-knowing rather than guessing
assert main.reconcile_unknown() == []
row = main.db().execute("SELECT state FROM payments WHERE id=?", (r_timeout["payment_id"],)).fetchone()
assert row["state"] == "UNKNOWN", dict(row)

# reconciliation asks the rail directly — it must never resubmit the payment
resolved = main.reconcile_unknown()
assert any(x["payment_id"] == r_timeout["payment_id"] and x["resolved_as"] == "SETTLED" for x in resolved), resolved
row = main.db().execute("SELECT state FROM payments WHERE id=?", (r_timeout["payment_id"],)).fetchone()
assert row["state"] == "SETTLED", dict(row)
events = [s["event"] for s in main.replay(r_timeout["payment_id"])["steps"]]
assert events[-1] == "reconciled", events
assert main.budget("race-agent")["reserved"] == 0  # moved from held to spent

# reconciliation is explicit, never a side effect of reading the budget: an UNKNOWN
# payment must stay UNKNOWN (and stay reserved) until an operator/job reconciles it
r_timeout2 = pay("inv-timeout-2", main.TIMEOUT_TRIGGER)
assert r_timeout2["state"] == "UNKNOWN"
b = main.budget("race-agent")
row = main.db().execute("SELECT state FROM payments WHERE id=?", (r_timeout2["payment_id"],)).fetchone()
assert row["state"] == "UNKNOWN", dict(row)  # reading the budget must NOT resolve it
assert b["reserved"] >= main.TIMEOUT_TRIGGER, b  # and the money stays held meanwhile
main.reconcile_unknown()  # first ask: rail says pending
main.reconcile_unknown()  # second ask: rail confirms
row = main.db().execute("SELECT state FROM payments WHERE id=?", (r_timeout2["payment_id"],)).fetchone()
assert row["state"] == "SETTLED", dict(row)

# --- router skips a rail marked down and picks the next-cheapest ---
main.RAIL_STATUS["x402_rail"] = "down"
r2 = pay("inv-rail-a", 10000)
assert r2["decision"] == "settled" and r2["rail"] == "card_rail", r2  # card_rail is next-cheapest (150bps)

# --- all rails down: fail closed, no payment, budget released ---
for _name in main.RAIL_STATUS:
    main.RAIL_STATUS[_name] = "down"
assert all(v == "down" for v in main.RAIL_STATUS.values()), main.RAIL_STATUS
r3 = pay("inv-no-rails", 10000)
assert r3["decision"] == "failed" and "unavailable" in r3["reason"], r3
assert main.budget("race-agent")["reserved"] == 0
main.RAIL_STATUS.update(main.default_rail_status())  # reset to whatever may be up

# --- a rail with nowhere to send money cannot be switched on -----------------
# A clone with no .env has no gateway. The panel used to let you bring the live rail
# up anyway; the router then picked it on price and urllib raised on the empty URL,
# which escaped as a 500 and left the payment stuck in EXECUTING holding budget.
class _Loopback:
    """The smallest thing operator_only() will accept."""
    client = type("c", (), {"host": "127.0.0.1"})()
    headers = {}

_saved_url, main.LIVE_RAIL_URL = main.LIVE_RAIL_URL, ''
try:
    main.set_rail_status("live_rail", main.RailStatus(status="up"), _Loopback())
    raise AssertionError("brought up a live rail with no gateway")
except main.HTTPException as e:
    assert e.status_code == 409, e.status_code

# and if it is up anyway, the submit fails cleanly instead of raising
main.RAIL_STATUS.update({"card_rail": "down", "x402_rail": "down", "live_rail": "up"})
_before = main.budget("ops-agent")["available"]
r_nogw = pay("inv-no-gateway", 10000)
assert r_nogw["decision"] == "failed", r_nogw
assert main.budget("ops-agent")["available"] == _before, "reservation was not released"
main.LIVE_RAIL_URL = _saved_url
main.RAIL_STATUS.update(main.default_rail_status())

# --- an unexpected error from a rail is UNKNOWN, never a crash ---------------
# We do not know whether the rail received it, so the money stays held and
# reconciliation asks. The one thing it must never do is escape as a 500.
_real_submit = main._rail_submit
def _boom(*a): raise RuntimeError("rail exploded")
main._rail_submit = _boom
try:
    r_boom = pay("inv-rail-explodes", 10000)
finally:
    main._rail_submit = _real_submit
assert r_boom["decision"] == "reconciling", r_boom
_row = main.db().execute("SELECT state FROM payments WHERE invoice_ref=?",
                         ("inv-rail-explodes",)).fetchone()
assert _row["state"] == "UNKNOWN", dict(_row)

# --- an operator's rail choice survives the reset every scenario runs first ---
# Until this, taking two rails down and clicking a scenario routed through x402_rail
# anyway: the reset put all three back up before the payment was ever attempted.
class _Loopback:
    """The smallest thing operator_only() will accept."""
    client = type("c", (), {"host": "127.0.0.1"})()
    headers = {}

main.RAIL_STATUS["x402_rail"] = "down"
main.post_demo_reset(_Loopback(), rails=False)
assert main.RAIL_STATUS["x402_rail"] == "down", main.RAIL_STATUS
main.post_demo_reset(_Loopback())          # the dock Reset button, which does restore them
assert main.RAIL_STATUS["x402_rail"] == "up", main.RAIL_STATUS

print("Phase 5: all checks passed")
