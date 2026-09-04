# Payment Firewall for AI Agents

### If we don't fully trust AI, how do we safely give it real-world power?

AI is already writing our emails, summarizing our information, managing our workflows, and increasingly acting on our behalf. And it's still not perfectly reliable — it hallucinates, misreads intent, gets manipulated, does the unexpected.

We keep asking it to act anyway.

Money is one of the sharpest versions of that problem. We're comfortable letting AI touch our words and our schedules. Handing it a payment API is a different kind of trust.

So the real question isn't *"how do we make AI trustworthy enough to hand it money?"*

It's: **how do we design a system where the AI doesn't need to be perfect, because the system around it won't let a mistake become a loss?**

That's what this is.

---

## Payment Firewall

A safety layer that sits between an autonomous AI agent and a payment API. The agent can request payments. It never gets unrestricted control over money.

> **Let the agent ask. Let deterministic rules enforce. Let AI reason only where it helps. Let humans decide when the system is uncertain. Always leave an audit trail.**

Hard financial limits are enforced deterministically. Suspicious behavior is detected from computed facts, not vibes. Ambiguous transactions get paused for a human. Failures and timeouts are handled without ever blindly retrying money out the door. Every decision is logged, hash-chained, and replayable.
We hand most work to models now, and mostly that is fine, because a bad draft is cheap to
catch and cheaper to fix. Money does not work that way. It is the most personal thing you
can hand to something you do not fully trust, and a payment that leaves is gone. So the
thing worth building is not a more reliable model. It is a ledger that stays correct while
the model is wrong.

It is not stuck behind our dashboard either. The firewall speaks MCP, the protocol AI clients
use to call tools, so it works as a service rather than a demo. Four tools, no glue code, and
any model that connects gets the same rules, the same ledger and the same audit chain as
every other payment. Point an agent at it and the safety layer comes along for the ride.

**Perks of the house**

- **Razorpay, actually wired in.** Test mode with real credentials, and a payment routed
  there creates a real order on Razorpay's side.
- **Bring your own gateway.** Razorpay is one rail out of three. Add another and the router
  picks whichever is cheapest and currently up, then fails over when it is not.
- **Speaks MCP out of the box.** Four tools: pay, check budget, list what is waiting on a
  human, and explain any past payment. The agent can ask about the money it is not allowed
  to move.
- **Nothing to set up to try it.** One Python file, one SQLite file, no queue and no broker.
  The live rail stays switched off until you hand it keys, so a fresh clone runs offline.

---

## How do you trust an unreliable AI?

You don't. That is the whole answer, and everything below is the consequence of taking it
seriously.

We tried the other way first. The model scored payments and decided which ones needed a
human. It escalated a payment *smaller* than the agent's own average, to a merchant it had
already paid six times, and gave "first-time merchant" as the reason. The input said that
was false. Seven of eight routine payments ended up in the approval queue, each carrying a
justification that contradicted its own numbers.

So we took the decision away from it. Not the model. The decision.

```
     what the model can do            what it structurally cannot do
     ─────────────────────            ──────────────────────────────
     write one sentence of            approve a payment
     commentary on a payment          escalate one the rules allowed
     a rule already stopped           see any text the agent wrote
                                      change any outcome at all
```

The rules decide. The model annotates, and only ever on a payment that has already been
stopped. If it is unreachable, slow, or returns nonsense, the payment escalates to a human
anyway, because the rule had already made that call. You can unplug the model mid-demo and
nothing about the money changes.

That is the trick, and it is not clever: **stop asking the model to be right, and start
making its wrongness structurally unable to reach the money.**

---

## Problem taste: why this and not something easier

Agent spend controls are not a green field. Stripe Issuing has per-card limits and velocity
checks. Ramp and Brex have card policies. AWS AgentCore Payments ships reserve/commit
guardrails. Rain shipped an agent control layer. Formance published this architecture as a
blog post.

So the caps are not the interesting bit, and we are not going to pretend they were. Nine
policy checks (`main.py:884-935`). An afternoon.

Three things were genuinely hard, and they are the reason this exists:

| The hard bit | Why it is hard |
|---|---|
| **Two payments in the same millisecond** | The obvious budget check reads a number, then writes. Two requests read the same number before either writes, and both go through. You cannot patch this with a lock nearby. The read, every rule, and the write have to be one indivisible step. |
| **A rail that goes quiet** | You sent a payment. Nothing came back. Did the money move? Retrying pays twice. Calling it failed loses real money. Both are wrong, and picking one is what most systems do. |
| **Idempotency against an adversary** | Deduplicating a retry is easy. Deduplicating `inv-9001` from `іnv-9001`, where the first letter is a Cyrillic lookalike, is not. That one was a live hole here until the review in the last section. |

---

## What it does, layer by layer

```
   agent
     │  signed intent
     ▼
  ┌────────────────────────────────────────────────────────────┐
  │ L0  gateway            verify_intent()      main.py:1092   │
  │ L1  idempotency        canon_invoice()      main.py:160    │
  │ L2  policy + ledger    decide()             main.py:807    │──► BLOCKED
  │        ── one transaction, no gap ──                       │
  │ L3  risk signals       compute_signals()    main.py:646    │
  │ L4  escalation rule    rule_review()        main.py:677    │
  └────────────────────────────────────────────────────────────┘
     │                              │
     │ allow                        │ escalate
     │                              ▼
     │                  L5  human queue     resolve_approval()  main.py:1030
     │                              │              │
     │                        approve            deny / expire ──► DENIED / EXPIRED
     │                              │
     ▼◄─────────────────────────────┘
  L6  router               pick_rail()          main.py:455
  L7  execution            execute_payment()    main.py:520
     │
     ├──► SETTLED        ├──► FAILED        └──► UNKNOWN
                                                   │
                                   L8  reconcile   reconcile_unknown()  main.py:591
                                       ask the rail, never resend
                                                   │
                                          SETTLED  /  FAILED

  every step ──►  L9  audit()  main.py:270  ──►  hash-chained  ──►  replay()  main.py:313
```

**Layer 0, gateway.** Every request arrives signed, not with a bearer key. The agent proves
it holds the secret without ever sending it, and the signature covers the request body, so
the amount in the audit trail is provably the amount the agent authorised. Change a digit in
transit and it stops verifying. Send the same request twice and the second one is refused,
because each intent carries a one-time value that gets burned on use. Money is stored in
whole paise, never floats, so rounding errors have nowhere to accumulate.

**Layer 1, idempotency.** A payment's identity is the agent, the merchant, and the invoice
reference. Same invoice, same amount, means a retry: you get the original result back and
nothing new is paid. Same invoice, different amount, means something is wrong, so it is
blocked for review rather than assumed to be a correction. The invoice reference is
normalised first, which sounds boring and is the reason six near-identical spellings of one
invoice no longer buy six payments.

**Layer 2, policy and the reservation ledger.** The deterministic core. Every agent has a
daily cap, a single-transaction cap, and a rolling one-hour velocity cap. The velocity cap
exists because an agent refused one large payment will otherwise try several small ones
that add up to the same thing, and each one passes the per-transaction check on its own. A
new agent with no settlement history is also held to a ₹500 ceiling until it has earned a
track record, since there is nothing yet to compare its behaviour against.

The duplicate check, all nine rules, and the write that commits the money happen inside a
single database transaction that holds an exclusive lock. A second request arriving
mid-flight waits, then reads the number the first one already wrote. There is no window
between checking and committing, because there is no gap to fit one in.

**Layer 3, risk signals.** Before anything else looks at the payment, the system computes
plain facts: how big this payment is next to the agent's own average, whether this merchant
is new to this agent, how many transactions have happened in the last hour, how much history
exists at all. Six numbers and booleans. Below three settled payments there is no average to
compare against, so the risk step is skipped outright rather than guessing from nothing.

**Layer 4, the escalation rule.** A payment is held for a human when it is five times the
agent's own average **and** going somewhere it has never paid, or ten times its average
regardless of destination. That is the whole rule. It is deterministic, it is the same every
run, and it is the only thing that can send a payment to the queue. The model gets consulted
afterwards, writes one sentence, and changes nothing.

**Layer 5, the human queue.** An escalated payment sits in `PENDING_APPROVAL` with its money
still held and a fifteen-minute clock running. Approving requires a written reason, always,
because an override with no explanation is not an audit trail. Two people clicking approve
and deny at the same instant is a real thing, so the first decision wins and the second gets
told it lost rather than silently overwriting. If nobody acts, the payment expires, the
reservation is released, and the money goes back.

**Layer 6, the router.** Three rails, and they behave differently on purpose. The card rail
answers inside the request: the money moved or it did not. The x402 rail hands back an
acknowledgement, and the real outcome arrives later. The router picks the cheapest rail
that is currently up and fails over automatically. If every rail is down, nothing is sent
and the reservation is released. Failing closed is the point.

**Layer 6, continued: a real gateway sits behind that same router.** The third rail is not a
mock. `live_rail` posts to Razorpay in test mode using credentials read from `.env`
(`main.py:464`), and a payment routed there creates a real order on Razorpay's side. It is
the most expensive of the three at 200bps (`main.py:439`), so `pick_rail()` only reaches for
it when the cheaper two are down, and it starts down when no credentials are configured, so
a fresh clone behaves exactly as it did before this existed. The reason it is here is that
it makes the firewall a service rather than a closed demo. Anything that can talk to a
payment provider can be added as another rail, so a team keeps the gateway it already uses
and gets the policy, the ledger and the audit chain in front of it.

**Layer 7, execution and the state machine.** `RESERVED` becomes `EXECUTING`, which becomes
`SETTLED`, `FAILED`, or `UNKNOWN`. That third one is the interesting state and it only
exists on the async rail. A timeout does not mean the payment failed. It means nobody knows,
and money that may have moved must not be quietly sent again.

**Layer 8, reconciliation.** For an `UNKNOWN` payment, the system asks the rail what
happened to that specific payment. It never resubmits. The answer resolves it to `SETTLED`
or `FAILED`, and the hold either becomes spend or goes back to available. This is deliberate
and manual: looking at your budget does not quietly reconcile things behind your back,
because the whole point is that a human sees the unresolved state and decides.

**Layer 9, audit, hash chain, replay.** Every transition is recorded, including refusals
that never became a payment at all. Each entry carries the fingerprint of the one before it,
so editing, deleting, or reordering any entry breaks that entry and every entry after it.
One endpoint walks the whole chain and reports whether it holds. Another reconstructs a
single payment's entire life in order, with a validity mark on each step, so a reviewer can
see both what happened and whether the record of it has been touched.

**Layer 10, the same firewall as an MCP server.** Everything above is an HTTP API, which
means somebody has to write integration code before an AI agent can use it. MCP is the
protocol that lets a model call tools directly, so `mcp_server.py` publishes four of them:
`pay`, `check_budget`, `list_pending_approvals` and `explain_payment`. Point an MCP client
at that file and a model can spend money with no glue code at all.

It decides nothing. Each tool signs a request and sends it to the same `/pay` the dashboard
uses (`mcp_server.py:40`), so a payment that arrives over MCP lands in the ledger, the state
machine and the hash chain identically to one from a script. Nothing in `main.py` knows MCP
exists.

The one thing this layer does differently is how it says no. A tool that raises an error
invites a model to try again, so a refusal comes back as a plain sentence instead: "Blocked
by policy. Do not retry this payment", and "Held for human approval. Do not re-send it; a
person will decide" (`mcp_server.py:85`). The model reads why it was stopped rather than
guessing that something went wrong.

```
   model  ──►  mcp_server.py  ──►  signed HTTP  ──►  L0 to L9  ──►  ledger + audit chain
                 4 tools           the same one          the same policy
                                   any agent uses        as every other payment
```

You do not need an MCP client to see it. The first scenario in the demo dock asks the
firewall to launch one itself (`main.py:1462`) and narrates a single tool call at a time, so
the agent's payments show up in the tables while you are still reading why it made them.

---

## The three-bucket money model

This is the part worth understanding, because everything else leans on it.

```
  DAILY LIMIT
      │
      ├── SPENT        money from completed, settled payments
      │
      ├── RESERVED     money committed to pending or in-flight payments
      │
      └── AVAILABLE    what is actually left to use
```

Reserved money is neither spent nor available. It is held against the budget for the entire
time a payment is awaiting approval, executing, or unresolved, and it only becomes spend, or
returns to available, once the outcome is definite.

A hold ends when the payment reaches a final state. Never when a timer runs out. A payment
that has been sitting in `UNKNOWN` for twenty-five hours still has that money locked away,
because nobody has confirmed where it went, and pretending otherwise would be the same
mistake as retrying it.

That single rule is what makes the concurrency guarantee possible. **40 payments released at
the same instant against a ₹5,000 cap: 20 settled, 20 blocked, exactly ₹5,000 committed.**
Not ₹5,000.25. Weaken the lock and that test fails, which we checked by weakening it on
purpose.

---

## Run it

Python 3.10 or newer. Four dependencies.

```bash
pip install -r requirements.txt
python main.py
```

Open **http://127.0.0.1:8000**, then click **Demo Mode** at the bottom right and pick a
scenario.

A local model is optional. Without one, the status chip says the engine is offline and
failing closed, and every payment outcome stays exactly the same, because the rules were
always the ones deciding. If you want it running: `ollama pull llama3.2`.

To run the tests:

```bash
python test_phase1.py && python test_phase2.py && python test_phase3.py && \
python test_phase4.py && python test_phase5.py && python test_phase6.py && \
python test_phase7.py && python test_http.py && python test_concurrency.py && \
python test_budget_hold.py
```

Ten suites, about 19 seconds, each on its own throwaway database.

---

## The ten demo scenarios

| | Scenario | What you are watching for |
|---|---|---|
| 1 | **Agent over MCP** | A real MCP client connects and asks for four payments in a row. One settles, one is a duplicate, one is blocked, one is held for a human. The agent never decides. |
| 2 | **Clean payment** | The happy path. Money goes out, the ledger moves, the audit chain grows. |
| 3 | **Duplicate invoice** | The same invoice sent twice. The second one replays the first result instead of paying again. |
| 4 | **Velocity / structuring** | Three payments, each perfectly fine alone, that add up to a pattern. The third is refused. |
| 5 | **Concurrent budget race** | Two payments fired at the same instant at one budget. Exactly one wins. |
| 6 | **Risk escalation** | An unusual payment held for a human, with the actual numbers that triggered it shown next to the decision. |
| 7 | **Rail timeout** | The rail goes quiet. The money stays held, the screen says DO NOT RETRY, and reconciliation asks rather than resends. |
| 8 | **All rails down** | Nothing is sent, the reservation is released. Failing closed, visibly. |
| 9 | **Runaway agent** | An agent stuck in a loop firing 75 payments. 60 get through, 15 are refused before they ever reach the ledger. |
| 10 | **Run a full day** | Six invoices on one agent, narrated. Watch the budget fill until the last one bounces off the cap. |

Scenario 7 is the one to watch if you only watch one. Most systems handle a timeout by
retrying, which risks paying twice, or by giving up, which loses track of real money. This
one refuses to guess.

---

## What broke, and how we got out

Five review passes over the finished code, each aimed at a different layer. Every bug below
was reproduced against a running system before it was fixed, and each one now has a test
that fails if it comes back.

**A denied payment settled on retry.**
Caught by: replaying a denied invoice byte for byte.
Before: the ledger held `DENIED 90000 "FRAUD - DO NOT PAY"` and `SETTLED 90000` for the same
invoice. After: blocked.
Why: denying a payment quietly freed its invoice reference, and the guard against retrying a
refusal only covered one of the two ways a payment can get escalated.
Fix: check for a prior refusal on every path (`main.py:880`), and a test that covers both
branches instead of one.

**The daily cap could be exceeded by ₹4,000.**
Caught by: stalling the advisory model call until the housekeeping sweep ran.
Before: ₹12,000 settled against an ₹8,000 cap. After: ₹7,000 settled, no overrun.
Why: one state write on the money path had no guard on what it was overwriting. The sweep
correctly released a stranded reservation, and then the escalation wrote over that released
row and took the money back.
Fix: the same guard every other state write already had (`main.py:973`). The dashboard's
overrun counter had been flagging it correctly the whole time, which is the part of that
story that worked.

**Six settlements for one invoice.**
Caught by: feeding Unicode variants of a single invoice reference.
Before: 6 payments, ₹3,000. After: 1 payment, ₹500, and 7 correctly recognised as repeats.
Why: invoice references were compared exactly, character for character. Zero-width
characters, accents, six different kinds of hyphen, and Cyrillic letters that look identical
to Latin ones all counted as different invoices.
Fix: normalise aggressively before comparing, and refuse any invoice reference that is not
plain ASCII (`main.py:160`), because no amount of normalisation makes a Cyrillic `і` equal a
Latin `i`.

**Every demo scenario ignored which rails were switched off.**
Caught by: taking two rails down in the dashboard, then clicking a scenario.
Before: `x402_rail` and `live_rail` switched off by hand, and the payment still settled on
`x402_rail`. After: settled on `card_rail`, the one rail left up.
Why: nothing was wrong with the router. Every scenario clears the ledger before it runs, and
clearing the ledger also put all three rails back up, so an operator's choice was undone a
fraction of a second before the payment was attempted.
Fix: the reset leaves rails alone unless it is asked to restore them (`main.py:1518`), and
only the dashboard's Reset button asks. The "all rails down" scenario now puts back exactly
what it switched off in a `finally` (`static/app.js:938`), because nothing else restores
them any more.

**A passing test was hiding the first bug on this list.**
Caught by: mutation testing. Breaking things on purpose and checking whether anything noticed.
Before: 20 of 32 deliberate defects caught. After: 30 of 32.
Why: there is a test named "a denial sticks". It passed the entire time. It exercised one of
the two denial paths and never touched the one that was broken.
Fix: three new suites written against the list of defects nothing had noticed, rather than
against the code.

That last one repeated itself while writing this document. A window test we had just added
aged payments by two hours, which does not distinguish a one-hour window from a one-minute
one, so the defect slipped through again. It now ages by thirty minutes first.

Two deliberate defects still survive, and both are honest. Swapping a constant-time string
comparison for a normal one changes timing, not behaviour, so no functional test can see it.
Dropping a field from the audit hash still leaves the chain detectable by a second
independent check.

---

## Tech stack

| Layer | What we used | Why |
|---|---|---|
| API | FastAPI | Typed request models and automatic validation at the trust boundary |
| Storage | SQLite | Its exclusive-lock transaction is what makes the concurrency guarantee real, and it needs no server |
| Auth | HMAC-signed intents, stdlib `hmac` | The secret never travels; the signature covers the body |
| Risk rules | Plain Python | Deterministic, testable, same answer every run |
| Advisory model | Local Ollama, `llama3.2`, temperature 0 | Runs offline, reproducible, and nothing depends on it |
| Frontend | Vanilla HTML, CSS and JS | No build step. Open the file and read it |
| Signing in-browser | WebCrypto | So no agent secret is ever baked into the page |
| Tests | Plain `assert` scripts | No framework to install; every suite runs standalone |
| Server | uvicorn | One command to start |

Three installed dependencies in total: FastAPI, uvicorn, pydantic. Everything else is the
Python standard library, including the HTTP client that talks to the model.

---

## API

| Method | Path | What it does |
|---|---|---|
| `POST` | `/pay` | Submit a signed payment intent. The only endpoint an agent may call |
| `GET` | `/payments` | Recent payments |
| `GET` | `/payments/{id}` | One payment's current state |
| `GET` | `/budget/{agent_id}` | Spent, reserved and available for one agent |
| `GET` | `/agents` | Configured agents and their caps |
| `GET` | `/approvals` | The human queue, with time remaining on each |
| `POST` | `/approvals/{id}/approve` | Approve, reason required. Operator only |
| `POST` | `/approvals/{id}/deny` | Deny, reason required. Operator only |
| `POST` | `/reconcile` | Resolve unknown payments by asking the rail. Operator only |
| `GET` | `/rails` | Rail status, fee and settlement type |
| `POST` | `/rails/{name}/status` | Take a rail up or down, for demoing failover. Operator only |
| `GET` | `/replay/{id}` | One payment's full decision history, each step hash-checked |
| `GET` | `/audit` | Recent audit entries |
| `GET` | `/audit/verify` | Walk the entire hash chain and report whether it holds |
| `GET` | `/metrics` | Aggregates for the dashboard |
| `POST` | `/demo/reset` | Clear history for a repeatable demo. Operator only |

Operator endpoints refuse anything that is not a local request. `/pay` refuses anything that
is not correctly signed.

---

## Scoreboard

| | |
|---|---|
| Test suites | 10, no framework |
| Full run | 18 seconds |
| Backend | 1,542 lines of Python |
| Frontend | 1,182 lines, no build step |
| Tests | 1,135 lines |
| Mutation kill rate | 20/32 before the audit, **30/32** after |
| Dependencies | 4 |
| Concurrency | 40 simultaneous payments, exactly ₹5,000 committed against a ₹5,000 cap |

---

