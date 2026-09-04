"""Phase 2 self-check: approval-queue state machine + 15-min TTL. Run: python test_phase2.py"""
import tempfile
import threading
import time
from pathlib import Path

import main

main.DB_PATH = Path(tempfile.mkdtemp()) / "test_firewall.db"
main.init_db()

# The model is not the subject of this suite. These agents currently stay below
# RISK_MIN_HISTORY by accident, so one extra settling payment would silently introduce a
# live Ollama call. Pin it closed.
def _no_model(_signals):
    raise AssertionError("risk_review must not be reached in this suite")


main.risk_review = _no_model


OPS = "key-ops-123"


def escalate(invoice):
    # one unregistered account per invoice: denying a payout account now blacklists it,
    # so reusing a single string here would block every later escalation in this suite
    return main.decide(OPS, "acme-supplies", invoice, 50000, "INR", f"ATTACKER-{invoice}")


# escalated payment reserves budget and carries an expiry
r = escalate("inv-1")
assert r["decision"] == "pending" and r["state"] == "PENDING_APPROVAL", r
pid = r["payment_id"]
assert r["expires_at"] > int(time.time()), r
assert main.budget("ops-agent")["reserved"] == 50000

# approving without a reason is refused — override must leave a paper trail
bad = main.resolve_approval(pid, "approve", "priya", reason=None)
assert bad["decision"] == "rejected" and "reason" in bad["reason"], bad

# approve with a reason -> settles, budget moves from reserved to spent
ok = main.resolve_approval(pid, "approve", "priya", reason="known new vendor account, verified by phone")
assert ok["decision"] == "settled" and ok["state"] == "SETTLED", ok
b = main.budget("ops-agent")
assert b["spent"] == 50000 and b["reserved"] == 0, b

# deny path releases the reservation entirely (not spent, not held)
r2 = escalate("inv-2")
pid2 = r2["payment_id"]
den = main.resolve_approval(pid2, "deny", "priya", reason="unverified account change")
assert den["decision"] == "denied" and den["state"] == "DENIED", den
b = main.budget("ops-agent")
assert b["reserved"] == 0 and b["spent"] == 50000, b  # unchanged from before

# approving an already-resolved payment is a conflict, not a silent no-op
again = main.resolve_approval(pid2, "approve", "someone-else", reason="too late")
assert again["decision"] == "conflict", again

# approval race: two humans decide the same item at once -> exactly one wins
r3 = escalate("inv-3")
pid3 = r3["payment_id"]
outcomes = []
threads = [
    threading.Thread(target=lambda actor=a: outcomes.append(
        main.resolve_approval(pid3, "approve", actor, reason="race test")))
    for a in ("alice", "bob")
]
[t.start() for t in threads]
[t.join() for t in threads]
assert sorted(o["decision"] for o in outcomes) == ["conflict", "settled"], outcomes

# expiry: simulate the clock running out -> auto-denied, reservation released, budget freed
r4 = escalate("inv-4")
pid4 = r4["payment_id"]
assert main.budget("ops-agent")["reserved"] == 50000
conn = main.db()
conn.execute("UPDATE payments SET expires_at=? WHERE id=?", (int(time.time()) - 1, pid4))
conn.close()
b = main.budget("ops-agent")  # budget() sweeps expired approvals before computing
assert b["reserved"] == 0, b
row = main.db().execute("SELECT state FROM payments WHERE id=?", (pid4,)).fetchone()
assert row["state"] == "EXPIRED", dict(row)

# a decision attempt on an already-expired item is a conflict, not a second denial
late = main.resolve_approval(pid4, "deny", "priya", reason="too slow")
assert late["decision"] == "conflict" and "EXPIRED" in late["reason"], late

# list_pending only shows live, non-expired items and reports time left
r5 = escalate("inv-5")
pending = main.list_pending()
assert len(pending) == 1 and pending[0]["id"] == r5["payment_id"]
assert 0 < pending[0]["seconds_remaining"] <= main.APPROVAL_TTL_SECONDS

# a denial sticks: the same payout account cannot come back under a fresh invoice_ref
# (race-agent, not ops-agent: ops-agent's 1hr velocity cap is fully committed by now)
RACE = "key-race-456"
d = main.decide(RACE, "acme-supplies", "inv-6", 50000, "INR", "ATTACKER-STICKY")
assert d["decision"] == "pending", d
assert main.resolve_approval(d["payment_id"], "deny", "priya", reason="fraudulent account")["decision"] == "denied"
retry = main.decide(RACE, "acme-supplies", "inv-7", 50000, "INR", "ATTACKER-STICKY")
assert retry["decision"] == "blocked" and "denied by human review" in retry["reason"], retry

print("Phase 2: all checks passed")
