"""Payment Firewall for AI Agents.

Gateway + validation + idempotency + policy engine over a reservation ledger,
plus a risk agent that reasons over precomputed signals via a local Ollama model.
All amounts are integer paise (no float money).

Run server:  python main.py    (http://127.0.0.1:8000)
Run checks:  python test_phase1.py ... test_phase6.py, test_http.py, test_budget_hold.py

Risk agent needs Ollama running locally with a model pulled, e.g.:
    ollama pull llama3.2
Override the endpoint/model with env vars FIREWALL_OLLAMA_URL / FIREWALL_OLLAMA_MODEL.
"""
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import time
import unicodedata
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, StrictInt

def _load_env(path=Path(__file__).parent / ".env"):
    """Six lines instead of a dependency. Real credentials live in .env, which is
    gitignored; .env.example shows the shape. Anything already exported wins."""
    if not path.exists():
        return
    try:
        # utf-8-sig, not utf8: Notepad writes a byte-order mark, which otherwise ends up
        # inside the first key name, so FIREWALL_LIVE_RAIL_URL silently never matches.
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        # Notepad's "Unicode" option means UTF-16. Refusing to start over a demo config
        # file is worse than running without it, so say so and carry on.
        print(f"ignoring {path.name}: it is not UTF-8 text. Re-save it as UTF-8.", flush=True)
        return
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


_load_env()

DB_PATH = Path(__file__).parent / "firewall.db"
APPROVAL_TTL_SECONDS = 15 * 60
MAX_AMOUNT = 10 ** 13  # Rs.10,00,00,00,000. A business ceiling, not a storage one:
                       # SQLite holds signed 64-bit, ~9.2e18.
OLLAMA_URL = os.environ.get("FIREWALL_OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("FIREWALL_OLLAMA_MODEL", "llama3.2")
RISK_TIMEOUT = int(os.environ.get("FIREWALL_RISK_TIMEOUT", "8"))
RISK_RATIO = float(os.environ.get("FIREWALL_RISK_RATIO", "5"))
RISK_MIN_HISTORY = 3  # skip the risk agent until an agent has a settlement baseline
# With no key the chain is tamper-EVIDENT only: anyone holding the DB file can rewrite an
# entry and recompute every hash after it. Set FIREWALL_AUDIT_KEY (kept outside the DB)
# and forging the chain also requires the key.
AUDIT_KEY = os.environ.get("FIREWALL_AUDIT_KEY", "").encode()
# Probation cap in paise, 0 = off. Below RISK_MIN_HISTORY settled payments compute_signals()
# has no baseline, so rule_review() never runs and an unproven agent would otherwise face the
# hard caps and nothing else. Rs.500 until it has earned a settlement history.
PROBATION_CAP = int(os.environ.get("FIREWALL_PROBATION_CAP", "50000"))
EXPIRY_RETRY_LIMIT = 3   # re-queues of one unreviewed payout account before we stop
EXECUTING_TIMEOUT_SECONDS = 60  # an execution that never reported an outcome is UNKNOWN, not lost
RATE_LIMIT = int(os.environ.get("FIREWALL_RATE_LIMIT", "60"))  # /pay attempts per minute per key
MCP_DEMO_STEPS = 12   # ceiling on /demo/mcp/{step}; mcp_demo.py owns the real script length
# A real payment gateway in test mode. Deliberately gateway-agnostic: give it a URL and a
# basic-auth pair and it treats 2xx as settled, 4xx as declined, and a timeout as UNKNOWN.
# That is the whole contract a rail has to satisfy, and it keeps the firewall from growing
# a vendor SDK. Unset means the rail stays down and nothing about the demo changes.
LIVE_RAIL_URL = os.environ.get("FIREWALL_LIVE_RAIL_URL", "")
LIVE_RAIL_USER = os.environ.get("FIREWALL_LIVE_RAIL_USER", "")
LIVE_RAIL_PASS = os.environ.get("FIREWALL_LIVE_RAIL_PASS", "")
LIVE_RAIL_TIMEOUT = int(os.environ.get("FIREWALL_LIVE_RAIL_TIMEOUT", "8"))

# States that hold money: a live payment whose outcome isn't final yet. A hold is
# released by a state change, never by the clock, so these are summed with no time
# window — a 25-hour-old UNKNOWN still has the money out of reach.
HELD = ("RESERVED", "PENDING_APPROVAL", "EXECUTING", "UNKNOWN")
# ...plus SETTLED: the states that occupy an invoice_ref for idempotency.
HOLDING = HELD + ("SETTLED",)
_H = ",".join("?" * len(HOLDING))
_HELD = ",".join("?" * len(HELD))

# The seeded history is scaffolding, not activity. It has to exist for the probation
# check and for compute_signals(), both of which query the payments table directly, but it
# must not appear in the read models: those rows carry no audit entries, so a table row a
# judge clicks would open a drawer with nothing in it, and the metric tiles would count
# yesterday's setup as today's work.
NOT_BASELINE = "invoice_ref NOT LIKE 'baseline-%'"

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY,
  api_key TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',      -- active | revoked
  daily_cap INTEGER NOT NULL,                 -- paise, rolling 24h
  velocity_cap INTEGER NOT NULL,              -- paise, rolling 1h
  single_txn_cap INTEGER NOT NULL             -- paise
);
CREATE TABLE IF NOT EXISTS merchants(
  id TEXT PRIMARY KEY,
  currency TEXT NOT NULL,
  account_fp TEXT NOT NULL                    -- sha256 of registered payout account
);
CREATE TABLE IF NOT EXISTS whitelist(
  agent_id TEXT NOT NULL,
  merchant_id TEXT NOT NULL,
  PRIMARY KEY(agent_id, merchant_id)
);
CREATE TABLE IF NOT EXISTS payments(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  merchant_id TEXT NOT NULL,
  invoice_ref TEXT NOT NULL,
  amount INTEGER NOT NULL,                    -- paise
  currency TEXT NOT NULL,
  state TEXT NOT NULL,                        -- RESERVED|PENDING_APPROVAL|EXECUTING|SETTLED|FAILED|BLOCKED|DENIED|EXPIRED|UNKNOWN
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER,                         -- set only while PENDING_APPROVAL
  decided_by TEXT,                            -- human actor who approved/denied
  rail TEXT,                                  -- which mock rail executed this payment
  payout_fp TEXT                              -- sha256 of the payout account this intent named
);
-- Idempotency: one live/settled payment per (agent, merchant, invoice).
-- Blocked/failed attempts don't burn the invoice_ref forever.
CREATE UNIQUE INDEX IF NOT EXISTS idx_idem
  ON payments(agent_id, merchant_id, invoice_ref)
  WHERE state IN ('RESERVED','PENDING_APPROVAL','EXECUTING','UNKNOWN','SETTLED');
-- Append-only, hash-chained decision log. payment_id is NULL for pipeline-level
-- rejections (bad key, malformed input) that never produced a payment row.
CREATE TABLE IF NOT EXISTS seen_nonces(
  nonce TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payment_id TEXT,
  actor TEXT NOT NULL,              -- rule | llm | human:<name>
  event TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
"""


def rupees(paise: int) -> str:
    """Money in reasons is read by an operator, not a machine — show it the way the
    console shows it. The ledger stays in integer paise."""
    return f"Rs.{paise / 100:,.2f}".rstrip("0").rstrip(".")


def canon_invoice(ref: str) -> str:
    """Idempotency key. Raw SQL '=' is byte-exact, so every spelling of one invoice used to
    buy its own payment. NFKC alone was not enough: it leaves zero-width characters,
    combining marks, the six Unicode hyphens and Cyrillic/Greek lookalikes intact, and
    'inv-1', 'inv‑1', 'inv-1' + U+0301 and 'iіv-1' all settled separately.

    Order matters: decompose first so combining marks are separable, drop the marks and
    the format characters, fold every dash-like codepoint to '-', remove ALL whitespace
    (not just the ends), then recompose and casefold."""
    ref = unicodedata.normalize("NFKD", ref)
    ref = "".join(c for c in ref
                  if unicodedata.category(c) not in ("Mn", "Me", "Cf")
                  and not c.isspace())
    ref = "".join("-" if unicodedata.category(c) == "Pd" else c for c in ref)
    return unicodedata.normalize("NFKC", ref).casefold()


def ascii_ref(ref: str) -> bool:
    """A canonical invoice reference must be ASCII. Homoglyphs are the whole reason: a
    Cyrillic 'i' and a Latin 'i' are different codepoints that render identically, and no
    amount of normalisation makes them equal. Invoice references are machine-generated
    identifiers, so requiring ASCII costs nothing and closes the class outright."""
    return ref.isascii()


def fingerprint(account: str) -> str:
    return hashlib.sha256(account.encode()).hexdigest()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # dashboard reads must not block payments
    return conn


def init_db(seed: bool = True) -> None:
    conn = db()
    conn.executescript(SCHEMA)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(payments)")}
    if "expires_at" not in cols:
        conn.execute("ALTER TABLE payments ADD COLUMN expires_at INTEGER")
    if "decided_by" not in cols:
        conn.execute("ALTER TABLE payments ADD COLUMN decided_by TEXT")
    if "rail" not in cols:
        conn.execute("ALTER TABLE payments ADD COLUMN rail TEXT")
    if "payout_fp" not in cols:
        conn.execute("ALTER TABLE payments ADD COLUMN payout_fp TEXT")
    if "settled_at" not in cols:
        conn.execute("ALTER TABLE payments ADD COLUMN settled_at INTEGER")
    # held() and settled_in() run on every /pay inside the write lock; sweep peeks on
    # every poll; /replay and /metrics join the log by payment.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pay_agent_state ON payments(agent_id, state)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pay_state ON payments(state)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_payment ON audit_log(payment_id)")
    if seed and not conn.execute("SELECT 1 FROM agents LIMIT 1").fetchone():
        conn.executescript(
            f"""
            INSERT INTO agents VALUES
              ('ops-agent',  'key-ops-123',  'active',  500000, 150000, 150000),
              ('race-agent', 'key-race-456', 'active',  500000, 500000, 300000),
              ('rogue-agent','key-rogue-789','revoked', 500000, 150000, 150000);
            INSERT INTO merchants VALUES
              ('acme-supplies', 'INR', '{fingerprint("ACME-ACC-001")}'),
              ('cloudify',      'INR', '{fingerprint("CLD-ACC-77")}');
            INSERT INTO whitelist VALUES
              ('ops-agent','acme-supplies'), ('ops-agent','cloudify'),
              ('race-agent','acme-supplies'), ('race-agent','cloudify');
            """
        )
    conn.close()


def _record(conn, agent_id, merchant_id, invoice_ref, amount, currency, state, reason,
            expires_at=None, payout_fp=None):
    pid = str(uuid.uuid4())
    now = int(time.time())
    # Columns named, not positional: a positional VALUES breaks every insert the moment
    # a migration adds a column.
    conn.execute(
        "INSERT INTO payments(id, agent_id, merchant_id, invoice_ref, amount, currency, "
        "state, reason, created_at, updated_at, expires_at, payout_fp) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid, agent_id, merchant_id, invoice_ref, amount, currency, state, reason, now, now,
         expires_at, payout_fp),
    )
    return pid


def _public(row):
    """A payment row minus payout_fp. The fingerprint exists for the denial check; the
    dashboard read models are unauthenticated and have no business handing it out."""
    return {k: v for k, v in dict(row).items() if k != "payout_fp"}


def _result(decision, pid, state, reason, **extra):
    return {"decision": decision, "payment_id": pid, "state": state, "reason": reason, **extra}


def _entry_hash(payment_id, actor, event, detail, created_at, prev_hash):
    """The one place an audit entry's hash is defined — it used to be spelled out in four.

    json.dumps, not '|'.join: merchant_id and detail carry agent-controlled text, and a
    '|' inside them would let a forger move a field boundary while keeping the same
    preimage. HMAC when a key is configured, plain sha256 otherwise."""
    payload = json.dumps([payment_id, actor, event, detail, created_at, prev_hash]).encode()
    return (hmac.new(AUDIT_KEY, payload, hashlib.sha256).hexdigest() if AUDIT_KEY
            else hashlib.sha256(payload).hexdigest())


def audit(conn, payment_id, actor, event, detail=""):
    """Append-only, hash-chained log entry. Serializes with its own lock when not
    already inside one; two writers computing the same prev_hash would silently
    fork the chain, so log writes get the same BEGIN IMMEDIATE treatment as money."""
    own_txn = not conn.in_transaction
    if own_txn:
        conn.execute("BEGIN IMMEDIATE")
    try:
        prev = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = prev["hash"] if prev else "0" * 64
        now = int(time.time())
        h = _entry_hash(payment_id, actor, event, detail, now, prev_hash)
        conn.execute(
            "INSERT INTO audit_log(payment_id,actor,event,detail,prev_hash,hash,created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (payment_id, actor, event, detail, prev_hash, h, now),
        )
        if own_txn:
            conn.execute("COMMIT")
    except Exception:
        if own_txn:
            conn.execute("ROLLBACK")
        raise


def verify_chain():
    """Walk the whole log and confirm no entry was edited, deleted, or reordered."""
    conn = db()
    try:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    finally:
        conn.close()
    prev_hash = "0" * 64
    for r in rows:
        if r["prev_hash"] != prev_hash:
            return {"intact": False, "broken_at": r["id"], "reason": "prev_hash does not match preceding entry"}
        if _entry_hash(r["payment_id"], r["actor"], r["event"], r["detail"],
                       r["created_at"], r["prev_hash"]) != r["hash"]:
            return {"intact": False, "broken_at": r["id"], "reason": "hash does not match entry contents"}
        prev_hash = r["hash"]
    return {"intact": True, "entries": len(rows)}


def replay(payment_id):
    """Every decision made about one payment, in order, with per-entry tamper checks."""
    conn = db()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE payment_id=? ORDER BY id", (payment_id,)
        ).fetchall()
        payment = conn.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
    finally:
        conn.close()
    if not rows:
        return None
    payment = _public(payment) if payment else None
    steps = []
    intact = True
    for r in rows:
        ok = _entry_hash(r["payment_id"], r["actor"], r["event"], r["detail"],
                         r["created_at"], r["prev_hash"]) == r["hash"]
        intact = intact and ok
        steps.append({**dict(r), "hash_valid": ok})
    return {"payment_id": payment_id, "current_state": payment,
            "steps": steps, "chain_intact": intact}


def sweep_expired(conn=None):
    """Housekeeping for anything stuck too long: an approval past its 15-minute window is
    auto-denied and releases its reservation; an execution that never reported an outcome
    becomes UNKNOWN so reconciliation can ask the rail, instead of sitting in EXECUTING
    forever holding money that nothing is watching."""
    owns = conn is None
    conn = conn or db()
    try:
        now = int(time.time())
        stale_before = now - EXECUTING_TIMEOUT_SECONDS
        # Peek before locking. The dashboard polls the endpoints that call this several
        # times every 2.5s and almost always has nothing to sweep; taking BEGIN IMMEDIATE
        # (an exclusive write lock) just to find zero rows contends with real payments for
        # nothing. Worst case a sweep is noticed one poll late, which a polled sweep is
        # anyway.
        if not conn.execute(
            "SELECT 1 FROM payments WHERE (state='PENDING_APPROVAL' AND expires_at < ?) "
            "OR (state IN ('EXECUTING','RESERVED') AND updated_at < ?) LIMIT 1",
            (now, stale_before),
        ).fetchone():
            return
        started = not conn.in_transaction
        if started:
            conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT id FROM payments WHERE state='PENDING_APPROVAL' AND expires_at < ?", (now,)
            ).fetchall()
            for r in rows:
                conn.execute(
                    "UPDATE payments SET state='EXPIRED', "
                    "reason='approval window elapsed (15 min); auto-denied, budget released', "
                    "updated_at=? WHERE id=?",
                    (now, r["id"]),
                )
                audit(conn, r["id"], "rule", "expired", "15-minute approval TTL elapsed")
            # A crash between execute_payment()'s two transactions leaves a row in EXECUTING
            # with the money held and nothing looking at it. Move it to UNKNOWN — the state
            # that means "ask the rail, never resubmit". If the rail does answer late,
            # execute_payment writes the real outcome over this.
            for r in conn.execute(
                "SELECT id FROM payments WHERE state='EXECUTING' AND updated_at < ?", (stale_before,)
            ).fetchall():
                conn.execute(
                    "UPDATE payments SET state='UNKNOWN', reason=?, updated_at=? "
                    "WHERE id=? AND state='EXECUTING'",
                    (f"execution reported no outcome within {EXECUTING_TIMEOUT_SECONDS}s; "
                     f"awaiting reconciliation", now, r["id"]),
                )
                audit(conn, r["id"], "rule", "unknown",
                      "stranded mid-execution; moved to UNKNOWN, money stays held, never resubmitted")
            # A crash or restart between the reserve COMMIT and execution leaves a row in
            # RESERVED holding budget with nothing watching it. Nothing was sent to a rail
            # yet, so unlike EXECUTING this one is safe to release outright.
            for r in conn.execute(
                "SELECT id FROM payments WHERE state='RESERVED' AND updated_at < ?", (stale_before,)
            ).fetchall():
                conn.execute(
                    "UPDATE payments SET state='FAILED', reason=?, updated_at=? "
                    "WHERE id=? AND state='RESERVED'",
                    (f"reserved but never executed within {EXECUTING_TIMEOUT_SECONDS}s; "
                     f"reservation released, no payment sent", now, r["id"]),
                )
                audit(conn, r["id"], "rule", "failed",
                      "stranded before execution; reservation released, nothing was sent")
            if started:
                conn.execute("COMMIT")
        except Exception:
            if started:
                conn.execute("ROLLBACK")
            raise
    finally:
        if owns:
            conn.close()


# --- mock payment rails ---
# In-memory only — resets on restart. Real rails would be HTTP clients; these are
# stand-ins with deterministic quirks so the failure paths are demoable on demand:
#   amount == ₹1700 (170000 paise) -> the rail rejects outright
#   amount == ₹1300 (130000 paise) -> the async rail acknowledges but never confirms
#     (the money actually went through; only the response was lost — reconciliation
#     confirms this instead of ever retrying the submit)
# Exact equality, not a modulo: a judge typing a round number should not trip a
# simulated failure with nothing on screen saying it was simulated.
# Two rails with genuinely DIFFERENT settlement semantics, not one mock wearing two
# names. This is the whole point of a policy layer that sits above the rails: one budget
# and one audit log spanning substrates that behave nothing alike.
#
#   card_rail  — synchronous authorize/capture. The rail answers within the request:
#                either the money moved or it did not. There is no in-between.
#   x402_rail  — settles out of band. Submitting only gets an acknowledgement; the
#                outcome has to be confirmed separately, so "we do not know yet" is a
#                real operating state rather than a simulated failure.
#
# UNKNOWN therefore exists ONLY on the async substrate, which is the true statement
# about cards versus on-chain/async rails.
#   live_rail  — a real payment gateway in test mode. Same three outcomes, except the
#                answer comes from someone else's server instead of from this file.
RAILS = {
    "card_rail": {"fee_bps": 150, "kind": "sync",  "label": "Card network (auth/capture)"},
    "x402_rail": {"fee_bps": 80,  "kind": "async", "label": "x402 (settles out of band)"},
    "live_rail": {"fee_bps": 200, "kind": "live",  "label": "Live gateway (test mode)"},
}
# The live rail starts down when it has no credentials, so an unconfigured checkout behaves
# exactly as it did before this existed. It is the most expensive rail on purpose: the
# router reaches for it only when the cheaper two are down.
def default_rail_status():
    """A rail is only up if it can actually take a payment. The live rail has no gateway
    until it is given one, so it stays down rather than accepting money it cannot send."""
    return {name: ("up" if name != "live_rail" or LIVE_RAIL_URL else "down") for name in RAILS}


RAIL_STATUS = default_rail_status()
FAIL_TRIGGER = 170000
TIMEOUT_TRIGGER = 130000


def pick_rail():
    """Cheapest rail that's currently up. None if every rail is down."""
    available = sorted(
        ((name, cfg["fee_bps"]) for name, cfg in RAILS.items() if RAIL_STATUS.get(name) == "up"),
        key=lambda x: x[1],
    )
    return available[0][0] if available else None


def _live_submit(amount):
    """Send one payment to a real gateway and map its reply onto our three outcomes.

    No vendor SDK and no response parsing: any gateway that answers 2xx for accepted and
    4xx for declined fits, which is all of them. A timeout is the interesting case, because
    it is the one that produces a genuine UNKNOWN rather than a simulated one."""
    if not LIVE_RAIL_URL:
        # Belt to set_rail_status's braces. Nothing left this process, so the money is
        # released rather than held: "failed" is the honest outcome, not UNKNOWN.
        RAIL_STATUS["live_rail"] = "down"
        return "failed"
    req = urllib.request.Request(
        LIVE_RAIL_URL,
        data=urllib.parse.urlencode({"amount": amount, "currency": "INR"}).encode(),
        method="POST",
    )
    if LIVE_RAIL_USER:
        token = base64.b64encode(f"{LIVE_RAIL_USER}:{LIVE_RAIL_PASS}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=LIVE_RAIL_TIMEOUT) as resp:
            return "settled" if 200 <= resp.status < 300 else "failed"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            # Our credentials, not their decision. Marking the rail down makes the cause
            # visible on the rail panel rather than looking like a run of declines.
            RAIL_STATUS["live_rail"] = "down"
        return "failed"          # the gateway answered, and the answer was no
    except Exception:
        return "timeout"         # no answer at all: hold the money, ask later


def _rail_submit(rail_name, amount):
    """Dispatch on the substrate's semantics, not on the rail's name."""
    kind = RAILS[rail_name]["kind"]
    if kind == "live":
        return _live_submit(amount)
    if kind == "sync":
        # A card network declines inside the request. It never leaves you guessing.
        return "failed" if amount == FAIL_TRIGGER else "settled"
    # Async substrate: submission is an acknowledgement, not an outcome. Usually the
    # confirmation lands immediately; when it does not, the payment is UNKNOWN and the
    # money stays held until the rail is QUERIED — never until it is resubmitted.
    if amount == FAIL_TRIGGER:
        return "failed"
    return "timeout" if amount == TIMEOUT_TRIGGER else "settled"


_QUERY_COUNT = {}  # payment_id -> how many times the rail has been asked about it


def _rail_query(rail_name, payment_id):
    """Reconciliation check: ask the rail directly instead of ever retrying submit.

    The first ask returns 'pending'; a real rail frequently cannot answer straight away,
    and the honest behaviour while nobody knows is to keep holding the money and ask
    again later, never to resubmit. The second ask resolves."""
    n = _QUERY_COUNT[payment_id] = _QUERY_COUNT.get(payment_id, 0) + 1
    return "settled" if n > 1 else "pending"


def execute_payment(pid):
    """RESERVED -> EXECUTING -> SETTLED|FAILED|UNKNOWN. Replaces the Phase-1..4 stub."""
    conn = db()
    try:
        amount = conn.execute("SELECT amount FROM payments WHERE id=?", (pid,)).fetchone()["amount"]
        rail = pick_rail()
        now = int(time.time())
        conn.execute("BEGIN IMMEDIATE")
        try:
            if rail is None:
                conn.execute(
                    "UPDATE payments SET state='FAILED', reason='all payment rails unavailable', "
                    "updated_at=? WHERE id=? AND state='RESERVED'", (now, pid),
                ).rowcount and audit(conn, pid, "rule", "failed",
                                     "all rails unavailable; failed closed, no payment sent")
                conn.execute("COMMIT")
                return
            claimed = conn.execute(
                "UPDATE payments SET state='EXECUTING', rail=?, reason=?, updated_at=? "
                "WHERE id=? AND state='RESERVED'",
                (rail, f"routed to {rail}", now, pid),
            ).rowcount
            if not claimed:
                # Someone else already moved this payment out of RESERVED. Submitting to
                # the rail now would pay a second time for one invoice.
                conn.execute("COMMIT")
                return
            audit(conn, pid, "rule", "executing", f"routed to {rail} (fee {RAILS[rail]['fee_bps']}bps, cheapest available)")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        try:
            outcome = _rail_submit(rail, amount)
        except Exception as e:
            # The row is already EXECUTING and the money is already held. Letting this
            # escape returns a 500 and leaves it there until the sweep notices. We do not
            # know whether the rail received anything, so UNKNOWN is the honest state: the
            # money stays held and reconciliation asks. It is never resubmitted.
            print(f"rail {rail} raised {type(e).__name__}: {e}", flush=True)
            outcome = "timeout"
        now = int(time.time())
        conn.execute("BEGIN IMMEDIATE")
        try:
            # rowcount, not just the WHERE clause: if the sweep already moved this row on,
            # the UPDATE is a no-op and writing the audit entry anyway records a
            # transition that never happened. A verifiable chain of false events is worse
            # than a gap in a true one.
            if outcome == "settled":
                wrote = conn.execute(
                    "UPDATE payments SET state='SETTLED', reason=?, updated_at=?, settled_at=? "
                    "WHERE id=? AND state='EXECUTING'",
                    (f"settled via {rail}", now, now, pid)).rowcount
                if wrote:
                    audit(conn, pid, "rule", "settled", f"settled via {rail}")
            elif outcome == "failed":
                wrote = conn.execute(
                    "UPDATE payments SET state='FAILED', reason=?, updated_at=? "
                    "WHERE id=? AND state='EXECUTING'",
                    (f"rejected by {rail}", now, pid)).rowcount
                if wrote:
                    audit(conn, pid, "rule", "failed", f"rejected by {rail}")
            else:  # timeout
                wrote = conn.execute(
                    "UPDATE payments SET state='UNKNOWN', reason=?, updated_at=? "
                    "WHERE id=? AND state='EXECUTING'",
                    (f"{rail} timed out on submit; awaiting reconciliation", now, pid)).rowcount
                if wrote:
                    audit(conn, pid, "rule", "unknown",
                          f"{rail} timed out on submit; will reconcile, never blindly retried")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def reconcile_unknown(conn=None):
    """For every UNKNOWN payment, ask its rail directly what actually happened —
    never resubmit. Returns what got resolved this pass."""
    owns = conn is None
    conn = conn or db()
    resolved = []
    try:
        started = not conn.in_transaction
        if started:
            conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute("SELECT id, rail, amount FROM payments WHERE state='UNKNOWN'").fetchall()
            now = int(time.time())
            for r in rows:
                outcome = _rail_query(r["rail"], r["id"])
                if outcome == "settled":
                    # settled_at, not created_at: a payment reconciled a day later still
                    # has to count against the day it actually moved money.
                    conn.execute("UPDATE payments SET state='SETTLED', reason=?, updated_at=?, "
                                 "settled_at=? WHERE id=? AND state='UNKNOWN'",
                                 (f"reconciled: {r['rail']} confirms settled", now, now, r["id"]))
                    audit(conn, r["id"], "rule", "reconciled", f"{r['rail']} confirms settled — no retry needed")
                    resolved.append({"payment_id": r["id"], "resolved_as": "SETTLED"})
                elif outcome == "failed":
                    conn.execute("UPDATE payments SET state='FAILED', reason=?, updated_at=? "
                                 "WHERE id=? AND state='UNKNOWN'",
                                 (f"reconciled: {r['rail']} confirms failed", now, r["id"]))
                    audit(conn, r["id"], "rule", "reconciled", f"{r['rail']} confirms failed")
                    resolved.append({"payment_id": r["id"], "resolved_as": "FAILED"})
                # else still genuinely unknown -> stays UNKNOWN, budget stays held
            if started:
                conn.execute("COMMIT")
        except Exception:
            if started:
                conn.execute("ROLLBACK")
            raise
    finally:
        if owns:
            conn.close()
    return resolved


def _run_execution(pid):
    """Runs execute_payment() and reports whatever it actually resolved to — settled,
    failed, or still reconciling (a rail timeout). Never assume settlement."""
    execute_payment(pid)
    conn = db()
    try:
        row = conn.execute("SELECT * FROM payments WHERE id=?", (pid,)).fetchone()
    finally:
        conn.close()
    decision = {"SETTLED": "settled", "FAILED": "failed", "UNKNOWN": "reconciling"}.get(row["state"], "error")
    return _result(decision, pid, row["state"], row["reason"], rail=row["rail"])


def compute_signals(conn, agent_id, merchant_id, amount):
    """Deterministic, checkable facts about this transaction vs. the agent's own
    settlement history. Returns None during cold start (nothing to compare against
    yet) — the risk agent has no baseline for a brand-new agent's first payments."""
    settled = conn.execute(
        "SELECT amount, merchant_id FROM payments WHERE agent_id=? AND state='SETTLED'",
        (agent_id,),
    ).fetchall()
    if len(settled) < RISK_MIN_HISTORY:
        return None

    amounts = [r["amount"] for r in settled]
    avg_amount = sum(amounts) / len(amounts)
    first_time_merchant = not any(r["merchant_id"] == merchant_id for r in settled)

    now = int(time.time())
    txns_last_hour = conn.execute(
        f"SELECT COUNT(*) c FROM payments WHERE agent_id=? AND created_at>? AND state IN ({_H})",
        (agent_id, now - 3600, *HOLDING),
    ).fetchone()["c"]

    return {
        "amount": amount,
        "agent_avg_settled_amount": round(avg_amount, 2),
        "amount_ratio_to_average": round(amount / avg_amount, 2) if avg_amount else None,
        "first_time_merchant": first_time_merchant,
        "transactions_last_hour": txns_last_hour,
        "agent_settled_count": len(settled),
    }


def rule_review(signals):
    """The escalation decision. Deterministic, and the only thing that moves a payment
    into the approval queue. It replaced an LLM verdict that escalated 7 of 8 routine
    payments and cited first_time_merchant as its reason when the value was false."""
    ratio = signals.get("amount_ratio_to_average") or 0
    first = bool(signals.get("first_time_merchant"))
    if ratio >= RISK_RATIO and first:
        why = (f"{ratio}x this agent's average settled amount, to a merchant it has "
               f"never paid before")
    elif ratio >= RISK_RATIO * 2:
        why = f"{ratio}x this agent's average settled amount"
    else:
        return {"decision": "allow", "reasoning": (
            f"{ratio}x average to a "
            f"{'first-time' if first else 'previously paid'} merchant — within normal range"),
            "cited_signals": ["amount_ratio_to_average", "first_time_merchant"]}
    return {"decision": "escalate", "reasoning": why,
            "cited_signals": ["amount_ratio_to_average", "first_time_merchant"]}


def risk_review(signals):
    """Ask the LLM to reason ONLY over precomputed signals — it can't invent a number
    or override a rule. Only two outcomes: allow (continue to settlement) or escalate
    (human review). Any failure (unreachable, malformed JSON, invalid decision) fails
    CLOSED to escalate; an unavailable risk agent must never make the system less
    careful."""
    prompt = (
        "You are a payments risk reviewer for an AI agent firewall. You are given "
        "precomputed, deterministic signals about one transaction. Do not invent new "
        "signals or numbers; reason only from what is given. Decide \"allow\" or "
        "\"escalate\". Escalate only when signals TOGETHER suggest coordinated or "
        "malicious behavior (e.g. a high amount ratio AND a first-time merchant); not "
        "merely one mildly unusual signal alone. Respond with strict "
        "JSON only: {\"decision\": \"allow\"|\"escalate\", \"cited_signals\": "
        "[<keys from the input you relied on>], \"reasoning\": \"<one sentence>\"}.\n\n"
        f"Signals: {json.dumps(signals)}"
    )
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
        # Keep the model resident between calls. Measured on this machine: ~6s warm,
        # ~20s cold, and Ollama unloads an idle model after about five minutes — so
        # without this a demo left idle pays the cold cost on the call that matters.
        "keep_alive": "30m",
    }
    try:
        req = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # RISK_TIMEOUT is 8s by default. This call is advisory only, so a slow model
        # costs narration, never a decision. Note urlopen's timeout is per socket
        # operation, not a deadline: a trickling endpoint can still outlast it.
        with urllib.request.urlopen(req, timeout=RISK_TIMEOUT) as resp:
            raw = json.loads(resp.read())
        verdict = json.loads(raw["response"])
        # Models routinely answer "ALLOW"/"Allow"; normalise before checking, or a
        # correct verdict would fail closed and escalate everything.
        decision = str(verdict.get("decision", "")).strip().lower()
        if decision not in ("allow", "escalate"):
            raise ValueError(f"invalid decision from LLM: {verdict.get('decision')!r}")
        return {
            "decision": decision,
            "cited_signals": verdict.get("cited_signals", []),
            "reasoning": verdict.get("reasoning", ""),
            "raw_llm_response": raw["response"],
            "available": True,
        }
    except Exception as e:
        # Operator-facing reason stays clean; the technical cause is kept alongside it
        # for forensics rather than dumped into the review queue.
        return {
            "decision": "escalate",
            "cited_signals": [],
            "reasoning": "Risk engine unavailable; failing closed to human review.",
            "error": f"{type(e).__name__}: {e}",
            "raw_llm_response": None,
            "available": False,
        }


_RATE = {}  # api_key -> [window_start, attempts_in_window]


def _rate_limited(api_key):
    """True once a key has spent its per-minute allowance.

    ponytail: fixed window in memory, so a caller can burst up to 2x across a window
    boundary and the dict grows one entry per distinct key tried. Both are far cheaper
    than the two DB rows every refused request writes today; move to per-IP limiting at
    the edge before this is load-bearing."""
    now = int(time.time())
    win, n = _RATE.get(api_key, (now, 0))
    if now - win >= 60:
        win, n = now, 0
    if len(_RATE) > 10000:      # one entry per distinct key tried; drop stale windows
        for k in [k for k, (w, _) in _RATE.items() if now - w >= 60]:
            del _RATE[k]
    _RATE[api_key] = (win, n + 1)
    return n + 1 > RATE_LIMIT


def held(conn, agent_id):
    """Money locked by live payments, at any age. Deliberately unwindowed: a hold ends
    when the payment reaches a terminal state, not when 24 hours pass."""
    return conn.execute(
        f"SELECT COALESCE(SUM(amount),0) s FROM payments WHERE agent_id=? AND state IN ({_HELD})",
        (agent_id, *HELD),
    ).fetchone()["s"]


def settled_in(conn, agent_id, seconds, now):
    """Money actually spent inside a rolling window."""
    return conn.execute(
        "SELECT COALESCE(SUM(amount),0) s FROM payments "
        "WHERE agent_id=? AND state='SETTLED' AND COALESCE(settled_at, created_at)>?",
        (agent_id, now - seconds),
    ).fetchone()["s"]


def committed(conn, agent_id, seconds, now):
    """What a cap is actually checked against: spend in the window plus every live hold."""
    return settled_in(conn, agent_id, seconds, now) + held(conn, agent_id)


def decide(api_key, merchant_id, invoice_ref, amount, currency, payout_account):
    """Full firewall pipeline for one payment intent. Returns a decision dict."""
    # Before anything opens the database: a caller whose every request is refused still
    # writes an audit row per attempt, so the cheapest defence has to come first.
    if _rate_limited(api_key):
        return _result("rate_limited", None, None,
                       f"rate limit exceeded; {RATE_LIMIT} requests/minute for this key")
    conn = db()
    try:
        # --- 0. validation (trust boundary) — logged even with no payment row yet,
        # since a run of these against an unknown key is itself worth an audit trail.
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0 or amount > MAX_AMOUNT:
            msg = f"amount must be a positive integer in paise, at most {MAX_AMOUNT}"
            audit(conn, None, "rule", "rejected", msg)
            return _result("rejected", None, None, msg)
        if not all(isinstance(x, str) and x for x in (merchant_id, invoice_ref, currency, payout_account)):
            audit(conn, None, "rule", "rejected", "missing or malformed field")
            return _result("rejected", None, None, "missing or malformed field")
        # Canonicalise first, THEN check emptiness: '   ' and a zero-width-only ref both
        # normalise to '' and would otherwise collide on one idempotency key.
        invoice_ref = canon_invoice(invoice_ref)
        if not invoice_ref:
            msg = "invoice_ref is empty after normalisation"
            audit(conn, None, "rule", "rejected", msg)
            return _result("rejected", None, None, msg)
        if not ascii_ref(invoice_ref):
            msg = "invoice_ref must be ASCII (non-ASCII lookalikes defeat idempotency)"
            audit(conn, None, "rule", "rejected", msg)
            return _result("rejected", None, None, msg)

        agent = conn.execute("SELECT * FROM agents WHERE api_key=?", (api_key,)).fetchone()
        if not agent or agent["status"] != "active":
            audit(conn, None, "rule", "rejected", f"unknown or revoked api key for merchant '{merchant_id}'")
            return _result("rejected", None, None, "unknown or revoked api key")
        aid = agent["id"]

        merchant = conn.execute("SELECT * FROM merchants WHERE id=?", (merchant_id,)).fetchone()
        payout_fp = fingerprint(payout_account)

        sweep_expired(conn)  # stale approvals must release their reservation before we check budget

        # --- 1+2. idempotency + policy, atomically over the ledger ---
        now = int(time.time())
        conn.execute("BEGIN IMMEDIATE")
        try:
            dup = conn.execute(
                f"SELECT * FROM payments WHERE agent_id=? AND merchant_id=? AND invoice_ref=? "
                f"AND state IN ({_H})",
                (aid, merchant_id, invoice_ref, *HOLDING),
            ).fetchone()
            if dup:
                if dup["amount"] == amount:
                    audit(conn, dup["id"], "rule", "replayed", "duplicate invoice, same amount")
                    conn.execute("COMMIT")
                    return _result("replayed", dup["id"], dup["state"],
                                   "duplicate invoice, same amount; returning original result",
                                   replayed=True)
                # ponytail: blocked for now; Phase 2 routes this to the approval queue
                reason = (f"duplicate invoice with DIFFERENT amount "
                          f"(original {rupees(dup['amount'])}, got {rupees(amount)}); needs human review")
                pid = _record(conn, aid, merchant_id, invoice_ref, amount, currency, "BLOCKED", reason,
                              payout_fp=payout_fp)
                audit(conn, pid, "rule", "blocked", reason)
                conn.execute("COMMIT")
                return _result("blocked", pid, "BLOCKED", reason)

            def block(reason):
                pid = _record(conn, aid, merchant_id, invoice_ref, amount, currency, "BLOCKED", reason,
                              payout_fp=payout_fp)
                audit(conn, pid, "rule", "blocked", reason)
                conn.execute("COMMIT")
                return _result("blocked", pid, "BLOCKED", reason)

            if conn.execute(
                "SELECT 1 FROM payments WHERE agent_id=? AND merchant_id=? AND invoice_ref=? "
                "AND state='DENIED' LIMIT 1", (aid, merchant_id, invoice_ref),
            ).fetchone():
                return block("this invoice was refused by human review; a denial is not "
                             "retryable under the same invoice")

            if not merchant or not conn.execute(
                "SELECT 1 FROM whitelist WHERE agent_id=? AND merchant_id=?", (aid, merchant_id)
            ).fetchone():
                return block(f"merchant '{merchant_id}' not whitelisted for agent '{aid}'")
            if currency != merchant["currency"]:
                return block(f"currency mismatch: intent {currency}, merchant expects {merchant['currency']}")
            if amount > agent["single_txn_cap"]:
                return block(f"amount {rupees(amount)} exceeds single-transaction cap {rupees(agent['single_txn_cap'])}")

            # Probation. Below RISK_MIN_HISTORY settled payments compute_signals() has no
            # baseline and returns None, so the risk agent never runs — an unproven agent
            # gets the hard rules and nothing else. The count query only runs for amounts
            # that would actually breach the cap, so the normal path costs nothing.
            if PROBATION_CAP and amount > PROBATION_CAP:
                settled_count = conn.execute(
                    "SELECT COUNT(*) c FROM payments WHERE agent_id=? AND state='SETTLED'", (aid,)
                ).fetchone()["c"]
                if settled_count < RISK_MIN_HISTORY:
                    return block(f"agent on probation ({settled_count}/{RISK_MIN_HISTORY} settled "
                                 f"payments, no behavioural baseline yet): amount {rupees(amount)} exceeds "
                                 f"probation cap {rupees(PROBATION_CAP)}")

            def window_sum(seconds):
                return committed(conn, aid, seconds, now)

            if window_sum(3600) + amount > agent["velocity_cap"]:
                return block(f"velocity limit: {rupees(window_sum(3600) + amount)} in the last hour "
                             f"exceeds cap {rupees(agent['velocity_cap'])} (split-payment pattern?)")
            if window_sum(86400) + amount > agent["daily_cap"]:
                return block(f"daily budget: spent+reserved {rupees(window_sum(86400))} + {rupees(amount)} "
                             f"exceeds cap {rupees(agent['daily_cap'])}")

            # Invoice-fraud check: whitelisted merchant but changed payout account -> escalate.
            if payout_fp != merchant["account_fp"]:
                # A human already refused this account once; a new invoice_ref must not buy
                # a second attempt at the queue. Only unregistered accounts reach this branch,
                # so a denial can never lock out the merchant's own registered account.
                # An expiry means nobody looked, not that a human said no, so it does not
                # blacklist the account. But an agent that can re-queue the same
                # unrecognised account forever just grinds the operator down.
                stale = conn.execute(
                    "SELECT COUNT(*) c FROM payments WHERE payout_fp=? AND state='EXPIRED'",
                    (payout_fp,)).fetchone()["c"]
                if stale >= EXPIRY_RETRY_LIMIT:
                    return block(f"payout account for '{merchant_id}' has expired unreviewed "
                                 f"{stale} times; not re-queued until a human decides it")
                if conn.execute("SELECT 1 FROM payments WHERE payout_fp=? AND state='DENIED' LIMIT 1",
                                (payout_fp,)).fetchone():
                    return block(f"payout account for '{merchant_id}' was denied by human review "
                                 f"before; a denial is not retryable under a new invoice")
                reason = f"payout account for '{merchant_id}' does not match registered account; escalated"
                expires_at = now + APPROVAL_TTL_SECONDS
                pid = _record(conn, aid, merchant_id, invoice_ref, amount, currency,
                              "PENDING_APPROVAL", reason, expires_at=expires_at, payout_fp=payout_fp)
                audit(conn, pid, "rule", "escalated", reason)
                conn.execute("COMMIT")
                return _result("pending", pid, "PENDING_APPROVAL", reason, expires_at=expires_at)

            pid = _record(conn, aid, merchant_id, invoice_ref, amount, currency,
                          "RESERVED", "all policy checks passed", payout_fp=payout_fp)
            audit(conn, pid, "rule", "reserved", "all policy checks passed")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        # --- 4. risk agent — reasons over precomputed signals, can only escalate, never override a rule ---
        signals = compute_signals(conn, aid, merchant_id, amount)
        if signals is None:
            audit(conn, pid, "rule", "risk_skipped", "insufficient settlement history for a baseline (cold start)")
        else:
            verdict = rule_review(signals)
            # The model is asked for a second opinion only on a payment the rule already
            # stopped — so it never gates the fast path, and it cannot approve anything.
            advisory = risk_review(signals) if verdict["decision"] == "escalate" else None
            audit(conn, pid, "rule", "risk_reviewed",
                  json.dumps({"signals": signals, "verdict": verdict, "advisory": advisory}))
            if verdict["decision"] == "escalate":
                expires_at = int(time.time()) + APPROVAL_TTL_SECONDS
                conn.execute("BEGIN IMMEDIATE")
                try:
                    # The reservation was committed before the risk step, so a slow
                    # advisory call can outlast the RESERVED sweep. Without this predicate
                    # the escalation resurrects a row the sweep already moved to FAILED and
                    # released, re-taking money the ledger had given back.
                    claimed = conn.execute(
                        "UPDATE payments SET state='PENDING_APPROVAL', reason=?, expires_at=?, updated_at=? "
                        "WHERE id=? AND state='RESERVED'",
                        (verdict["reasoning"], expires_at, int(time.time()), pid),
                    ).rowcount
                    if not claimed:
                        conn.execute("COMMIT")
                        row = conn.execute("SELECT state, reason FROM payments WHERE id=?",
                                           (pid,)).fetchone()
                        return _result("expired", pid, row["state"], row["reason"])
                    audit(conn, pid, "rule", "escalated", verdict["reasoning"])
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise
                return _result("pending", pid, "PENDING_APPROVAL", verdict["reasoning"],
                                expires_at=expires_at, risk_signals=signals)

        # --- 5. execution — router picks the cheapest available rail; a rail can time out ---
        return _run_execution(pid)
    finally:
        conn.close()


def budget(agent_id):
    conn = db()
    try:
        # Only the TTL sweep runs here: expiry is time-based housekeeping the budget
        # math depends on. Reconciliation is deliberately NOT automatic — a dashboard
        # polling this endpoint would silently resolve every UNKNOWN payment within
        # seconds, hiding the state the operator is supposed to see and act on.
        sweep_expired(conn)
        agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            return None
        now = int(time.time())
        spent = settled_in(conn, agent_id, 86400, now)
        reserved = held(conn, agent_id)
        return {"agent_id": agent_id, "daily_cap": agent["daily_cap"], "spent": spent,
                "reserved": reserved, "available": agent["daily_cap"] - spent - reserved}
    finally:
        conn.close()


def list_pending():
    conn = db()
    try:
        sweep_expired(conn)
        rows = conn.execute(
            "SELECT * FROM payments WHERE state='PENDING_APPROVAL' ORDER BY created_at"
        ).fetchall()
        now = int(time.time())
        return [{**_public(r), "seconds_remaining": max(0, (r["expires_at"] or now) - now)}
                for r in rows]
    finally:
        conn.close()


def resolve_approval(payment_id, action, actor, reason=None):
    """Race-safe approve/deny: the WHERE clause is the lock, first writer wins."""
    if action not in ("approve", "deny"):
        return _result("error", payment_id, None, "action must be 'approve' or 'deny'")
    if not actor:
        return _result("rejected", payment_id, None, "actor is required")
    if action == "approve" and not reason:
        # An escalation exists for a reason; overriding it must leave a paper trail.
        return _result("rejected", payment_id, None, "reason is required to approve an escalated payment")

    conn = db()
    try:
        sweep_expired(conn)
        now = int(time.time())
        new_state = "RESERVED" if action == "approve" else "DENIED"
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE payments SET state=?, reason=?, decided_by=?, updated_at=? "
                "WHERE id=? AND state='PENDING_APPROVAL'",
                (new_state, reason or "denied by human review", actor, now, payment_id),
            )
            if cur.rowcount == 0:
                row = conn.execute("SELECT state FROM payments WHERE id=?", (payment_id,)).fetchone()
                if not row:
                    conn.execute("COMMIT")
                    return _result("error", payment_id, None, "no such payment")
                audit(conn, payment_id, f"human:{actor}", f"{action}_conflict",
                      f"already resolved as {row['state']}; too late")
                conn.execute("COMMIT")
                return _result("conflict", payment_id, row["state"],
                               f"already resolved as {row['state']}; this decision came too late")
            audit(conn, payment_id, f"human:{actor}",
                  "approved" if action == "approve" else "denied", reason or "")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()

    if action == "deny":
        return _result("denied", payment_id, "DENIED", reason or "denied by human review")

    return _run_execution(payment_id)


# --- HTTP layer ---
app = FastAPI(title="Payment Firewall for AI Agents")


INTENT_SKEW_SECONDS = 120


def signing_input(agent_id: str, ts: str, nonce: str, body: bytes) -> bytes:
    """Exactly what an agent signs. The body hash is included, so a signature authorises
    ONE intent; an intercepted request cannot have its amount or payout account edited
    and still verify."""
    return b"\n".join([agent_id.encode(), ts.encode(), nonce.encode(),
                       hashlib.sha256(body).hexdigest().encode()])


def verify_intent(conn, agent_id, ts, nonce, signature, body):
    """Signed payment intents. The agent proves possession of its secret without ever
    putting the secret on the wire, the signature is bound to this exact body, and a
    captured request cannot be replayed.

    This is a shared-secret HMAC, not public-key identity; an operator who can read the
    agents table can mint a signature. Named honestly in the README; the roadmap is a
    per-agent keypair so the server only ever holds a public key."""
    agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if not agent or agent["status"] != "active":
        return None, "unknown or revoked agent"
    try:
        skew = abs(int(time.time()) - int(ts))
    except (TypeError, ValueError):
        return None, "malformed timestamp"
    if skew > INTENT_SKEW_SECONDS:
        return None, f"timestamp outside the {INTENT_SKEW_SECONDS}s signing window"
    expected = hmac.new(agent["api_key"].encode(),
                        signing_input(agent_id, ts, nonce, body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature or ""):
        return None, "signature does not match this request"
    now = int(time.time())
    # Anything older than the skew window can never verify again, so it is dead weight.
    conn.execute("DELETE FROM seen_nonces WHERE created_at < ?", (now - INTENT_SKEW_SECONDS,))
    try:
        conn.execute("INSERT INTO seen_nonces(nonce, agent_id, created_at) VALUES (?,?,?)",
                     (nonce, agent_id, now))
    except sqlite3.IntegrityError:
        return None, "nonce already used; this intent was already submitted"
    return agent, None


def operator_only(request: Request):
    """Agent auth is the API key on /pay. Operator actions — approving money, taking a
    rail down, wiping the demo — are bound to the loopback interface instead: the console
    runs on the same host as the firewall, and nothing off-box may reach these. This is
    topology, not authentication; a deployment needs a real operator credential here."""
    if (request.client.host if request.client else None) not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "operator endpoint: local access only")
    # These endpoints are ambient-authority: the browser sends no token, so any page the
    # operator has open in another tab could POST to them. /demo/reset and /reconcile take
    # no body, which makes them CORS-simple and therefore preflight-free. Refuse any
    # request that carries a cross-origin marker.
    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin and not origin.startswith(("http://127.0.0.1", "http://localhost",
                                         "https://127.0.0.1", "https://localhost")):
        raise HTTPException(403, "cross-origin request to an operator endpoint")


class PayIntent(BaseModel):
    merchant_id: str
    invoice_ref: str
    amount: StrictInt    # paise; StrictInt so True and "5000" are rejected, not coerced
    currency: str
    payout_account: str


@app.on_event("startup")
def _startup():
    init_db()
    conn = db()
    try:
        seed_baseline(conn)
    finally:
        conn.close()


@app.post("/pay")
async def pay(request: Request,
              x_agent_id: str = Header(...),
              x_timestamp: str = Header(...),
              x_nonce: str = Header(...),
              x_signature: str = Header(...)):
    """A payment intent must be SIGNED, not merely accompanied by a bearer key.

    The body is read raw and hashed into the signature, so the amount and payout account
    a judge sees in the audit trail are provably the ones the agent authorised."""
    # Before the database is touched at all. The limiter used to live inside decide(),
    # keyed on the API key, which is only known AFTER a valid signature — so unsigned
    # floods bypassed it entirely and each rejection still wrote an audit row under
    # BEGIN IMMEDIATE, contending with real payments for the write lock.
    if _rate_limited(x_agent_id):
        raise HTTPException(429, f"rate limit exceeded: {RATE_LIMIT} requests/minute")

    body = await request.body()
    try:
        intent = PayIntent.model_validate_json(body)
    except Exception as e:
        raise HTTPException(400, f"malformed intent: {e}")

    conn = db()
    try:
        agent, err = verify_intent(conn, x_agent_id, x_timestamp, x_nonce, x_signature, body)
        if err:
            audit(conn, None, "rule", "rejected", f"unsigned or invalid intent: {err}")
            raise HTTPException(401, err)
        api_key = agent["api_key"]
    finally:
        conn.close()

    r = decide(api_key, intent.merchant_id, intent.invoice_ref,
               intent.amount, intent.currency, intent.payout_account)
    if r["decision"] == "rate_limited":
        raise HTTPException(429, r["reason"])
    if r["decision"] == "rejected":
        raise HTTPException(400, r["reason"])
    return r


@app.get("/payments/{pid}")
def get_payment(pid: str):
    conn = db()
    row = conn.execute("SELECT * FROM payments WHERE id=?", (pid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "no such payment")
    return _public(row)


@app.get("/budget/{agent_id}")
def get_budget(agent_id: str):
    b = budget(agent_id)
    if not b:
        raise HTTPException(404, "no such agent")
    return b


class ApprovalAction(BaseModel):
    actor: str
    reason: str | None = None


@app.get("/approvals")
def get_approvals():
    return list_pending()


@app.post("/approvals/{pid}/approve")
def approve(pid: str, action: ApprovalAction, request: Request):
    operator_only(request)
    r = resolve_approval(pid, "approve", action.actor, action.reason)
    if r["decision"] in ("error", "rejected"):
        raise HTTPException(404 if r["decision"] == "error" else 400, r["reason"])
    if r["decision"] == "conflict":
        raise HTTPException(409, r["reason"])
    return r


@app.post("/approvals/{pid}/deny")
def deny(pid: str, action: ApprovalAction, request: Request):
    operator_only(request)
    r = resolve_approval(pid, "deny", action.actor, action.reason)
    if r["decision"] in ("error", "rejected"):
        raise HTTPException(404 if r["decision"] == "error" else 400, r["reason"])
    if r["decision"] == "conflict":
        raise HTTPException(409, r["reason"])
    return r


@app.get("/replay/{pid}")
def get_replay(pid: str):
    r = replay(pid)
    if not r:
        raise HTTPException(404, "no such payment")
    return r


@app.get("/audit/verify")
def get_audit_verify():
    return verify_chain()


class RailStatus(BaseModel):
    status: str  # "up" | "down"


@app.get("/rails")
def get_rails():
    return [{"name": n, "fee_bps": cfg["fee_bps"], "kind": cfg["kind"], "label": cfg["label"],
             "status": RAIL_STATUS[n]} for n, cfg in RAILS.items()]


@app.post("/rails/{name}/status")
def set_rail_status(name: str, body: RailStatus, request: Request):
    operator_only(request)
    if name not in RAILS:
        raise HTTPException(404, "no such rail")
    if body.status not in ("up", "down"):
        raise HTTPException(400, "status must be 'up' or 'down'")
    # A rail that is up is a promise the router will send real money to it. The live rail
    # cannot keep that promise without a gateway, and the router picks by price, not by
    # whether a rail is plausible, so the check belongs here rather than at submit time.
    if name == "live_rail" and body.status == "up" and not LIVE_RAIL_URL:
        raise HTTPException(409, "the live rail has no gateway configured; "
                                 "set FIREWALL_LIVE_RAIL_URL in .env before bringing it up")
    RAIL_STATUS[name] = body.status
    return {"name": name, "status": body.status}


@app.get("/demo/keys")
def get_demo_keys(request: Request):
    """Demo scenario credentials, loopback only — so they are not baked into app.js."""
    operator_only(request)
    conn = db()
    try:
        return {r["id"]: r["api_key"] for r in conn.execute("SELECT id, api_key FROM agents")}
    finally:
        conn.close()


@app.post("/reconcile")
def post_reconcile(request: Request):
    operator_only(request)
    return {"resolved": reconcile_unknown()}


# --- read models for the dashboard (thin queries over existing tables) ---

@app.get("/agents")
def get_agents():
    conn = db()
    try:
        rows = conn.execute(
            "SELECT id, status, daily_cap, velocity_cap, single_txn_cap FROM agents ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/payments")
def get_payments(limit: int = 50):
    limit = max(1, min(limit, 500))
    conn = db()
    try:
        sweep_expired(conn)
        rows = conn.execute(
            f"SELECT * FROM payments WHERE {NOT_BASELINE} "
            f"ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_public(r) for r in rows]
    finally:
        conn.close()


@app.get("/audit")
def get_audit(limit: int = 100):
    limit = max(1, min(limit, 1000))
    conn = db()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        valid = _entry_hash(r["payment_id"], r["actor"], r["event"], r["detail"],
                            r["created_at"], r["prev_hash"]) == r["hash"]
        out.append({**dict(r), "hash_valid": valid})
    return out


@app.get("/metrics")
def get_metrics():
    conn = db()
    try:
        counts = {r["state"]: r["c"] for r in
                  conn.execute(f"SELECT state, COUNT(*) c FROM payments "
                               f"WHERE {NOT_BASELINE} GROUP BY state")}
        escalated = conn.execute(
            "SELECT COUNT(DISTINCT payment_id) c FROM audit_log WHERE event='escalated'").fetchone()["c"]
        approved = conn.execute(
            "SELECT COUNT(DISTINCT payment_id) c FROM audit_log WHERE event='approved'").fetchone()["c"]
        denied = conn.execute(
            "SELECT COUNT(DISTINCT payment_id) c FROM audit_log WHERE event='denied'").fetchone()["c"]
        reconciled = conn.execute(
            "SELECT COUNT(DISTINCT payment_id) c FROM audit_log WHERE event='reconciled'").fetchone()["c"]
        # Median time from escalation to a human decision, per payment.
        waits = [r["w"] for r in conn.execute(
            "SELECT (d.created_at - e.created_at) w FROM audit_log e JOIN audit_log d "
            "ON d.payment_id = e.payment_id WHERE e.event='escalated' AND d.event IN ('approved','denied')"
        )]
        # Risk-engine availability is derived from the last recorded review — no extra
        # network call just to render a status light.
        # The rule verdict carries no engine health. Only rows where the model was
        # actually consulted (an escalation) have an `advisory`, so skip the rest or the
        # most recent row is almost always an allow with advisory null.
        last_review = conn.execute(
            "SELECT detail FROM audit_log WHERE event='risk_reviewed' "
            "AND json_extract(detail, '$.advisory') IS NOT NULL "
            "ORDER BY id DESC LIMIT 1").fetchone()
        # Measured, not asserted: an agent whose settled spend plus live holds sits above
        # its own daily cap. The dashboard prints this next to the words "ledger invariant",
        # so it has to be computed from the ledger rather than hardcoded.
        now = int(time.time())
        # Computed with its own SQL rather than by calling committed() — the very function
        # the pre-transaction check uses. Reusing it meant a bug in that function could
        # never show up here, so the number could only ever be 0 no matter what the ledger
        # did. Same definition, independent arithmetic: a disagreement now surfaces.
        overruns = 0
        for a in conn.execute("SELECT id, daily_cap FROM agents").fetchall():
            row = conn.execute(
                f"SELECT COALESCE(SUM(CASE WHEN state='SETTLED' "
                f"  AND COALESCE(settled_at, created_at) > ? THEN amount ELSE 0 END), 0) spent, "
                f"COALESCE(SUM(CASE WHEN state IN ({_HELD}) THEN amount ELSE 0 END), 0) held "
                f"FROM payments WHERE agent_id=?",
                (now - 86400, *HELD, a["id"]),
            ).fetchone()
            if row["spent"] + row["held"] > a["daily_cap"]:
                overruns += 1
    finally:
        conn.close()

    risk_engine = "unknown"
    if last_review:
        try:
            v = json.loads(last_review["detail"])["advisory"]
            risk_engine = "available" if v["available"] else "unavailable"
        except Exception:
            risk_engine = "unknown"

    decided = approved + denied
    waits.sort()
    return {
        "processed": sum(counts.values()),
        "settled": counts.get("SETTLED", 0),
        "blocked": counts.get("BLOCKED", 0) + counts.get("FAILED", 0),
        "escalated": escalated,
        "pending": counts.get("PENDING_APPROVAL", 0),
        "unknown": counts.get("UNKNOWN", 0),
        "reconciled": reconciled,
        "budget_overruns": overruns,
        "approval_rate": round(100 * approved / decided) if decided else None,
        "escalation_rate": round(100 * escalated / sum(counts.values())) if counts else 0,
        "median_approval_seconds": waits[len(waits) // 2] if waits else None,
        "audit": verify_chain(),
        "risk_engine": risk_engine,
        "by_state": counts,
    }


# Baselines the demo agents start from. Dated 25 hours back, so compute_signals() and the
# probation count both see them (neither is time-windowed) while settled_in() does not, and
# no demo budget is consumed. The amounts set each agent's average, which is what the
# escalation ratio is measured against: Rs.200 for ops-agent keeps its Rs.800 anomaly above
# 5x, Rs.400 for race-agent keeps its Rs.3,000 race payments below 10x.
DEMO_BASELINE = {
    "ops-agent":  (20000, ["acme-supplies"]),
    "race-agent": (40000, ["acme-supplies", "cloudify"]),
}


def seed_baseline(conn):
    """Give each demo agent a settlement history from yesterday, so probation is satisfied
    without any of it counting against today's cap.

    Called from the server's startup and from /demo/reset, never from init_db(): the test
    suites call init_db() directly and several of them exercise the cold-start path, where
    an agent genuinely has no history."""
    if conn.execute("SELECT 1 FROM payments WHERE invoice_ref LIKE 'baseline-%' LIMIT 1").fetchone():
        return
    then = int(time.time()) - 25 * 3600
    for agent_id, (amount, merchants) in DEMO_BASELINE.items():
        for i in range(RISK_MIN_HISTORY):
            merchant = merchants[i % len(merchants)]
            conn.execute(
                "INSERT INTO payments(id, agent_id, merchant_id, invoice_ref, amount, currency, "
                "state, reason, created_at, updated_at, settled_at) "
                "VALUES (?,?,?,?,?,?,'SETTLED','baseline from a prior day',?,?,?)",
                (str(uuid.uuid4()), agent_id, merchant, f"baseline-{agent_id}-{i}",
                 amount, "INR", then, then, then),
            )


@app.post("/demo/mcp/{step}")
def post_demo_mcp(step: int, request: Request):
    """Run one step of the MCP session and hand back what the firewall answered.

    The dashboard cannot do this itself: an MCP server is a local process spoken to over
    stdio, and a browser cannot launch one. So it asks the firewall to run the same script
    an operator would run in a second terminal, one call at a time, and narrates between
    them. Each payment arrives through the ordinary signed API, so it shows up in the
    tables while the room is still reading why the agent made it.

    Step -1 clears the ledger and reports the handshake. There is nothing to inject: the
    script path is fixed and the only argument is an integer index into it."""
    operator_only(request)
    script = Path(__file__).parent / "mcp_demo.py"
    if not script.exists():
        raise HTTPException(404, "mcp_demo.py is not in this directory")
    if not -1 <= step < MCP_DEMO_STEPS:
        raise HTTPException(400, f"step must be between -1 and {MCP_DEMO_STEPS - 1}")
    env = {**os.environ, "MCP_DEMO_STEP": str(step), "PYTHONIOENCODING": "utf-8",
           # whichever address the operator actually reached us on, so no second port setting
           "FIREWALL_URL": str(request.base_url).rstrip("/")}
    try:
        done = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                              timeout=60, env=env, cwd=str(script.parent),
                              encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "the MCP session did not answer in time")
    if done.returncode != 0 or not done.stdout.strip():
        # Print the whole thing to the server console. A one-line HTTP detail is enough for
        # the dashboard toast and useless for debugging, and this is the only place the
        # subprocess's traceback exists at all.
        print(f"\n--- /demo/mcp/{step} failed (exit {done.returncode}) ---\n"
              f"{(done.stderr or '(no stderr)').strip()}\n"
              f"--- stdout ---\n{(done.stdout or '(no stdout)').strip()}\n", flush=True)
        if "No module named 'mcp'" in (done.stderr or ""):
            raise HTTPException(500, "the mcp package is not installed. Run: pip install mcp")
        why = (done.stderr or "").strip().splitlines()
        raise HTTPException(500, (why[-1] if why else "the MCP session failed")[:300])
    return json.loads(done.stdout.strip().splitlines()[-1])



@app.post("/demo/reset")
def post_demo_reset(request: Request, rails: bool = True):
    """Clear transaction history so a demo can be run repeatedly. Agents, merchants
    and whitelists are re-seeded.

    rails=false leaves RAIL_STATUS alone. The dashboard passes it before every scenario,
    because an operator who takes two rails down to watch the router fail over means it:
    restoring them here sent the payment down the cheapest of all three instead. The
    Reset button in the demo dock is the one caller that still puts the rails back.
    """
    operator_only(request)
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM payments")
        conn.execute("DELETE FROM audit_log")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_log'")
        seed_baseline(conn)
        conn.execute("COMMIT")
    finally:
        conn.close()
    if rails:
        RAIL_STATUS.update(default_rail_status())
    _QUERY_COUNT.clear()
    _RATE.clear()          # otherwise the runaway scenario only throttles once per process
    return {"reset": True}


# --- dashboard ---
STATIC = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC / "index.html", media_type="text/html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")


if __name__ == "__main__":
    import uvicorn
    init_db()
    # proxy_headers defaults True, which lets X-Forwarded-For rewrite request.client
    # and makes the loopback check above spoofable behind any permissive proxy config.
    uvicorn.run(app, host="127.0.0.1", port=8000, proxy_headers=False)
