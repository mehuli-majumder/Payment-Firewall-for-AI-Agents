"""The firewall, exposed as an MCP server.

An agent's model calls these tools instead of a payment provider's own MCP server, so
policy is enforced before anything reaches a rail. Nothing here decides anything: every
call goes through the same signed HTTP API a script would use, so an MCP-originated
payment lands in the ledger and the audit chain identical to any other.

Run the firewall first (python main.py), then point an MCP client at this file.

    FIREWALL_URL           default http://127.0.0.1:8000
    FIREWALL_AGENT_ID      default ops-agent
    FIREWALL_AGENT_SECRET  required; the agent's signing secret
"""
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
import uuid
import time

from mcp.server.mcpserver import MCPServer

FIREWALL = os.environ.get("FIREWALL_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_ID = os.environ.get("FIREWALL_AGENT_ID", "ops-agent")
SECRET = os.environ.get("FIREWALL_AGENT_SECRET", "")

server = MCPServer(
    name="payment-firewall",
    instructions=(
        "Submit payments through this firewall rather than directly to a payment provider. "
        "It enforces per-agent budget caps, velocity limits, duplicate-invoice detection and "
        "human approval. A refusal is final: do not retry a blocked payment, and do not "
        "re-send one that is awaiting human approval."
    ),
)


def _call(method, path, payload=None):
    """One request. Payments are signed; reads are not, matching the HTTP API exactly."""
    url = f"{FIREWALL}{path}"
    headers = {"Content-Type": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        ts, nonce = str(int(time.time())), str(uuid.uuid4())
        # Mirrors signing_input() in main.py: agent, timestamp, nonce, sha256(body).
        preimage = b"\n".join([AGENT_ID.encode(), ts.encode(), nonce.encode(),
                               hashlib.sha256(body).hexdigest().encode()])
        headers.update({
            "X-Agent-Id": AGENT_ID,
            "X-Timestamp": ts,
            "X-Nonce": nonce,
            "X-Signature": hmac.new(SECRET.encode(), preimage, hashlib.sha256).hexdigest(),
        })
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = json.loads(e.read() or b"{}").get("detail", e.reason)
        # A refusal is an answer, not a transport failure. Hand it back as text so the
        # model reads why it was refused rather than seeing a tool crash and retrying.
        return {"refused": True, "status": e.code, "reason": detail}
    except Exception as e:
        return {"error": f"the firewall is unreachable at {FIREWALL}: {e}"}


@server.tool(description="Submit a payment. The firewall decides whether it goes through.")
def pay(merchant_id: str, invoice_ref: str, amount_paise: int,
        payout_account: str, currency: str = "INR") -> str:
    """Amounts are in paise, so pass 50000 for Rs.500. Never floats."""
    if not SECRET:
        return "FIREWALL_AGENT_SECRET is not set, so this agent cannot sign a payment."
    r = _call("POST", "/pay", {
        "merchant_id": merchant_id, "invoice_ref": invoice_ref,
        "amount": amount_paise, "currency": currency, "payout_account": payout_account,
    })
    if r.get("error"):
        return r["error"]
    if r.get("refused"):
        return f"REFUSED ({r['status']}): {r['reason']}"
    decision = r.get("decision", "?")
    verdict = {
        "settled":     f"Paid. Routed via {r.get('rail', 'a rail')}.",
        "blocked":     "Blocked by policy. Do not retry this payment.",
        "pending":     "Held for human approval. Do not re-send it; a person will decide.",
        "replayed":    "Already paid. This invoice was settled earlier, so nothing was sent again.",
        "reconciling": "The rail did not confirm. The money is held and will not be resent.",
        "failed":      "The rail refused it. The reservation was released.",
        "rejected":    "Rejected before any policy check.",
    }.get(decision, "See the reason below.")
    return f"{decision.upper()}: {verdict}\nreason: {r.get('reason', '')}\npayment_id: {r.get('payment_id')}"


@server.tool(description="How much this agent has spent, has held, and can still spend today.")
def check_budget() -> str:
    r = _call("GET", f"/budget/{AGENT_ID}")
    if r.get("error"):
        return r["error"]
    rupees = lambda p: f"Rs.{p / 100:,.2f}"
    return (f"daily cap {rupees(r['daily_cap'])} | spent {rupees(r['spent'])} | "
            f"held {rupees(r['reserved'])} | available {rupees(r['available'])}")


@server.tool(description="Payments waiting on a human decision, and how long each has left.")
def list_pending_approvals() -> str:
    r = _call("GET", "/approvals")
    if isinstance(r, dict):
        return r.get("error") or str(r)
    if not r:
        return "Nothing is waiting for a human."
    return "\n".join(
        f"{p['id'][:8]}  Rs.{p['amount'] / 100:,.2f} to {p['merchant_id']}  "
        f"{p['seconds_remaining'] // 60}m left  ({p['reason']})" for p in r)


@server.tool(description="Every decision taken on one payment, in order, with the audit chain checked.")
def explain_payment(payment_id: str) -> str:
    r = _call("GET", f"/replay/{payment_id}")
    if r.get("error") or r.get("refused"):
        return r.get("error") or f"No record for {payment_id}."
    steps = "\n".join(f"  {s['event']:14} {s['actor']:12} {s['detail'][:90]}" for s in r["steps"])
    return (f"{payment_id}\nchain intact: {r['chain_intact']}\n{steps}")


if __name__ == "__main__":
    server.run()
