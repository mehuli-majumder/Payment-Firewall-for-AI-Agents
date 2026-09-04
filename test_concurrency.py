"""Concurrency self-check: the claim the whole project rests on.

test_phase1.py races two threads, which is enough to catch a missing lock. This races
forty, which is what the README claims, so the number in the docs is reproducible from
the repo rather than taken on trust.

The property: N simultaneous payments against one budget commit exactly the cap and not
one paise more. Remove BEGIN IMMEDIATE and this fails every run.

Run: python test_concurrency.py
"""
import tempfile
import threading
from pathlib import Path

import main

main.DB_PATH = Path(tempfile.mkdtemp()) / "test_firewall.db"
main.init_db()


def _no_model(_signals):
    raise AssertionError("risk_review must not be reached in this suite")


main.risk_review = _no_model

CAP = 500000
AMOUNT = 25000          # 20 of these fit the cap exactly
THREADS = 40            # so half must be refused

conn = main.db()
conn.execute("UPDATE agents SET daily_cap=?, velocity_cap=?, single_txn_cap=? WHERE id='race-agent'",
             (CAP, CAP, AMOUNT))
conn.close()

results = []
errors = []
start = threading.Barrier(THREADS)      # release every thread at the same instant


def fire(i):
    try:
        start.wait()
        r = main.decide("key-race-456", "acme-supplies", f"race-{i}", AMOUNT,
                        "INR", "ACME-ACC-001")
        results.append(r["decision"])
    except Exception as e:                # a thread that dies must not vanish silently
        errors.append(repr(e))


threads = [threading.Thread(target=fire, args=(i,)) for i in range(THREADS)]
for t in threads:
    t.start()
for t in threads:
    t.join()

assert not errors, f"threads raised: {errors[:3]}"
assert len(results) == THREADS, f"expected {THREADS} results, got {len(results)}"

settled = results.count("settled")
blocked = results.count("blocked")
assert settled + blocked == THREADS, f"unexpected decisions: {set(results)}"

conn = main.db()
committed = conn.execute(
    "SELECT COALESCE(SUM(amount),0) s FROM payments WHERE agent_id='race-agent' AND state='SETTLED'"
).fetchone()["s"]
conn.close()

# The whole point: not "roughly the cap", exactly the cap.
assert committed == CAP, f"committed {committed} against a cap of {CAP}"
assert settled == CAP // AMOUNT, f"{settled} settled, expected {CAP // AMOUNT}"
assert main.get_metrics()["budget_overruns"] == 0

# ...and the audit chain survived forty concurrent writers without forking.
chain = main.verify_chain()
assert chain["intact"], chain

print(f"Concurrency: {THREADS} simultaneous payments -> {settled} settled / {blocked} blocked, "
      f"committed exactly {committed} against a cap of {CAP}, chain intact "
      f"({chain['entries']} entries)")
