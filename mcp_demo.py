"""A narrated agent session over MCP, for running beside the dashboard.

This is a real MCP client. It launches mcp_server.py over stdio, does the protocol
handshake, discovers the tools, and calls them. The requests are scripted rather than
chosen by a model, so the demo is the same every time; everything below the tool call is
the live system, and each payment shows up in the dashboard as it happens.

    Terminal 1:  python main.py
    Terminal 2:  python mcp_demo.py
    Browser:     http://127.0.0.1:8000

Run: python mcp_demo.py
"""
import asyncio
import json
import os
import sys
import urllib.request

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PACE = float(os.environ.get("MCP_DEMO_PACE", "2.2"))   # seconds between steps

# Set by the dashboard, which narrates the run itself and wants one step at a time so each
# payment lands on screen while the room is still reading why it was made. -1 clears the
# ledger and reports the handshake; 0..n run one scripted call and print it as JSON.
STEP = os.environ.get("MCP_DEMO_STEP")

# What the agent asks for, in order, and why each one is interesting.
SCRIPT = [
    ("check_budget", {},
     "First it checks what it is allowed to spend."),
    ("pay", {"merchant_id": "acme-supplies", "invoice_ref": "mcp-demo-1",
             "amount_paise": 15000, "payout_account": "ACME-ACC-001"},
     "A routine invoice to a supplier it has paid before."),
    ("pay", {"merchant_id": "acme-supplies", "invoice_ref": "mcp-demo-1",
             "amount_paise": 15000, "payout_account": "ACME-ACC-001"},
     "The agent glitches and sends the same invoice again."),
    ("pay", {"merchant_id": "not-a-real-merchant", "invoice_ref": "mcp-demo-2",
             "amount_paise": 10000, "payout_account": "WHO-KNOWS"},
     "Now it tries a merchant nobody approved."),
    ("pay", {"merchant_id": "cloudify", "invoice_ref": "mcp-demo-3",
             "amount_paise": 120000, "payout_account": "CLD-ACC-77"},
     "And a large payment to a merchant it has never paid. Watch the dashboard."),
    ("list_pending_approvals", {},
     "The agent can see what it is waiting on. It cannot approve it."),
]

RULE = "─" * 74
FIREWALL = os.environ.get("FIREWALL_URL", "http://127.0.0.1:8000").rstrip("/")


def reset():
    """Clear the ledger before the session starts.

    Without this the second run replays every payment, because the invoice references are
    fixed and the first run already settled them. Not an MCP call: this is an operator
    clearing the board, which is why it goes straight to the firewall.

    rails=false so that an operator who has a rail switched off still sees the router use
    what is left, rather than the ledger clear quietly switching it back on."""
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"{FIREWALL}/demo/reset?rails=false", data=b"", method="POST"), timeout=10)
        return True
    except Exception as e:
        print(f"\n  could not reach the firewall at {FIREWALL}: {e}")
        print("  start it first:  python main.py\n")
        return False


def show(role, text):
    for i, line in enumerate(str(text).rstrip().splitlines()):
        print(f"  {role if i == 0 else '':<9} {line}")


async def main():
    env = {**os.environ}
    env.setdefault("FIREWALL_AGENT_SECRET", "key-ops-123")
    env.setdefault("FIREWALL_AGENT_ID", "ops-agent")
    here = os.path.dirname(os.path.abspath(__file__))
    params = StdioServerParameters(
        command=sys.executable, args=[os.path.join(here, "mcp_server.py")], env=env)

    if STEP is None:
        print(f"\n{RULE}\n  An agent connecting to the payment firewall over MCP\n{RULE}")
        if not reset():
            return
        print("\n  ledger cleared, so this runs the same way every time")
    elif STEP == "-1" and not reset():
        return
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = (await session.list_tools()).tools

            if STEP is not None:
                if STEP == "-1":
                    print(json.dumps({"server": init.server_info.name,
                                      "tools": [t.name for t in tools]}))
                    return
                tool, args, narration = SCRIPT[int(STEP)]
                result = await session.call_tool(tool, args)
                print(json.dumps({"narration": narration, "tool": tool, "args": args,
                                  "result": result.content[0].text,
                                  "last": int(STEP) == len(SCRIPT) - 1}))
                return
            print(f"\n  connected to  {init.server_info.name}")
            print(f"  tools offered  {', '.join(t.name for t in tools)}\n")
            await asyncio.sleep(PACE)

            for tool, args, narration in SCRIPT:
                print(RULE)
                print(f"  {narration}\n")
                asked = ", ".join(f"{k}={v}" for k, v in args.items()) or "(no arguments)"
                show("agent", f"calls {tool}({asked})")
                result = await session.call_tool(tool, args)
                print()
                show("firewall", result.content[0].text)
                print()
                await asyncio.sleep(PACE)

    print(RULE)
    print("  Every one of those decisions is in the ledger and the audit chain.")
    print("  The agent asked. It never decided.")
    print(f"{RULE}\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
