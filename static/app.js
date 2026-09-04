/* Payment Firewall — dashboard.
   Data access is confined to `api`; every render function is a pure function of the
   snapshot in `state`. Any mutation calls refresh(), which refetches and re-renders
   every dependent section — the boring equivalent of query invalidation. */

// ── api layer ────────────────────────────────────────────────────────────────
const api = {
  async req(path, opts = {}) {
    // opts spreads first: its `headers` must merge with the defaults, not replace them.
    const r = await fetch(path, {
      ...opts,
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      // FastAPI validation errors put an array of objects in `detail`.
      const detail = typeof body.detail === "string" ? body.detail
        : body.detail ? JSON.stringify(body.detail) : r.statusText;
      throw Object.assign(new Error(detail), { status: r.status, body });
    }
    return body;
  },
  agents:    ()            => api.req("/agents"),
  payments:  (limit = 50)  => api.req(`/payments?limit=${limit}`),
  approvals: ()            => api.req("/approvals"),
  budget:    (id)          => api.req(`/budget/${id}`),
  audit:     (limit = 100) => api.req(`/audit?limit=${limit}`),
  metrics:   ()            => api.req("/metrics"),
  rails:     ()            => api.req("/rails"),
  replay:    (pid)         => api.req(`/replay/${pid}`),
  verify:    ()            => api.req("/audit/verify"),
  reconcile: ()            => api.req("/reconcile", { method: "POST" }),
  // keepRails: a scenario clears the ledger but must not undo an operator's rail
  // switches, or taking a rail down to watch failover shows the same rail as before.
  reset:     (keepRails)   =>
    api.req(`/demo/reset${keepRails ? "?rails=false" : ""}`, { method: "POST" }),
  demoKeys:  ()            => api.req("/demo/keys"),
  mcpStep:   (n)           => api.req(`/demo/mcp/${n}`, { method: "POST" }),
  setRail:   (name, status) =>
    api.req(`/rails/${name}/status`, { method: "POST", body: JSON.stringify({ status }) }),
  decide:    (pid, action, actor, reason) =>
    api.req(`/approvals/${pid}/${action}`, { method: "POST", body: JSON.stringify({ actor, reason }) }),
  // A payment intent is signed, never sent with a bearer key. The secret stays in this
  // tab; what crosses the wire is an HMAC bound to this exact body, so the amount and
  // payout account cannot be edited in flight and the request cannot be replayed.
  pay: async (agentId, intent) => {
    const body = JSON.stringify(intent);
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomUUID();
    const sig = await sign(SECRETS[agentId], agentId, ts, nonce, body);
    return api.req("/pay", {
      method: "POST",
      headers: { "X-Agent-Id": agentId, "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig },
      body,
    });
  },
};

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

/* Mirrors signing_input() in main.py: agent, timestamp, nonce, sha256(body), newline-joined. */
async function sign(secret, agentId, ts, nonce, body) {
  const enc = new TextEncoder();
  const bodyHash = hex(await crypto.subtle.digest("SHA-256", enc.encode(body)));
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign(
    "HMAC", key, enc.encode([agentId, ts, nonce, bodyHash].join("\n"))));
}

// ── state ────────────────────────────────────────────────────────────────────
const OPERATOR = "operator";
const state = {
  view: "overview",
  agents: [], payments: [], approvals: [], budgets: {}, audit: [],
  metrics: null, rails: [], race: null, busy: false, focusAgent: "ops-agent",
};

// ── formatting ───────────────────────────────────────────────────────────────
const rupees = (paise) =>
  "₹" + (paise / 100).toLocaleString("en-IN", { minimumFractionDigits: 0, maximumFractionDigits: 2 });
const clockTime = (ts) => new Date(ts * 1000).toLocaleTimeString("en-IN", { hour12: false });
const mmss = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
const short = (id) => (id ? id.slice(0, 8) : "n/a");
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const STATE_STYLE = {
  SETTLED:          ["b-ok", "SETTLED"],
  EXECUTING:        ["b-info", "EXECUTING"],
  RESERVED:         ["b-info", "RESERVED"],
  PENDING_APPROVAL: ["b-warn", "PENDING APPROVAL"],
  BLOCKED:          ["b-err", "BLOCKED"],
  FAILED:           ["b-err", "FAILED"],
  DENIED:           ["b-err", "DENIED"],
  EXPIRED:          ["b-muted", "EXPIRED"],
  UNKNOWN:          ["b-unknown", "UNKNOWN"],
};
const stateBadge = (s) => {
  const [cls, label] = STATE_STYLE[s] || ["b-muted", s || "n/a"];
  return `<span class="badge ${cls}">${label}</span>`;
};
const riskBadge = (p) => {
  if (p.state === "PENDING_APPROVAL") return `<span class="badge b-warn">ESCALATED</span>`;
  if (["BLOCKED", "DENIED", "FAILED"].includes(p.state)) return `<span class="badge b-err">ELEVATED</span>`;
  return `<span class="badge b-muted">NORMAL</span>`;
};
const el = (id) => document.getElementById(id);

// ── toasts ───────────────────────────────────────────────────────────────────
function toast(title, msg, kind = "") {
  const node = document.createElement("div");
  node.className = `toast ${kind}`;
  node.innerHTML = `<b>${esc(title)}</b>${esc(msg || "")}`;
  el("toasts").appendChild(node);
  setTimeout(() => node.remove(), 4800);
}

// ── refresh (single invalidation point) ──────────────────────────────────────
async function refresh() {
  try {
    const [agents, payments, approvals, audit, metrics, rails] = await Promise.all([
      api.agents(), api.payments(), api.approvals(), api.audit(), api.metrics(), api.rails(),
    ]);
    Object.assign(state, { agents, payments, approvals, audit, metrics, rails });
    state.budgets = {};
    await Promise.all(
      agents.filter((a) => a.status === "active").map(async (a) => {
        state.budgets[a.id] = await api.budget(a.id);
      })
    );
    el("system-status").textContent = "OPERATIONAL";
    el("system-status").className = "ok";
  } catch (e) {
    el("system-status").textContent = "UNREACHABLE";
    el("system-status").className = "";
    return;
  }
  renderAll();
}

function renderAll() {
  renderHeader();
  renderMoneyCards();
  renderBudget();
  renderPipeline();
  renderApprovals();
  renderRace();
  renderReconciliation();
  renderPayments();
  renderProtectionEvents();
  renderMetrics();
  renderAudit();
  renderIntegrity();
  renderRails();
}

// ── primary agent: the one the demo drives ───────────────────────────────────
/* The panel must track the agent the running scenario actually drives — four scenarios
   use race-agent, and a bar pinned to ops-agent sits flat through the whole demo. */
const primaryAgent = () =>
  state.agents.find((a) => a.id === state.focusAgent) ||
  state.agents.find((a) => a.id === "ops-agent") ||
  state.agents.find((a) => a.status === "active");
const totals = () => {
  const a = primaryAgent();
  const b = a && state.budgets[a.id] ? [state.budgets[a.id]] : Object.values(state.budgets);
  return {
    cap:       b.reduce((s, x) => s + x.daily_cap, 0),
    spent:     b.reduce((s, x) => s + x.spent, 0),
    reserved:  b.reduce((s, x) => s + x.reserved, 0),
    available: b.reduce((s, x) => s + x.available, 0),
  };
};

// ── header ───────────────────────────────────────────────────────────────────
function renderHeader() {
  const a = primaryAgent();
  el("foot-agent").textContent = a ? a.id : "n/a";
  el("foot-agent-status").textContent = a ? a.status.toUpperCase() : "n/a";

  const engine = state.metrics?.risk_engine ?? "unknown";
  const chip = el("risk-engine-status");
  chip.textContent = { available: "ONLINE", unavailable: "OFFLINE: FAILING CLOSED",
                       unknown: "IDLE" }[engine];
  chip.className = engine === "available" ? "ok" : "";
  chip.style.color = engine === "unavailable" ? "var(--warn)" : "";

  const n = state.approvals.length;
  const badge = el("nav-approval-count");
  badge.hidden = n === 0;
  badge.textContent = n;

  // No rail up means nothing can be paid at all — surface it from every view, not
  // just the rail tab, so the console is never silently in a blocking state.
  const alert = el("global-alert");
  const noRails = state.rails.length && state.rails.every((r) => r.status === "down");
  alert.hidden = !noRails;
  if (noRails) {
    alert.innerHTML = `
      <div class="banner">
        <div class="banner-title">PAYMENT BLOCKED: ALL RAILS UNAVAILABLE</div>
        <div class="banner-sub">No trusted payment rail is available. Reservations are released and no payment is sent. The firewall fails closed.</div>
      </div>`;
  }
}

// ── money cards ──────────────────────────────────────────────────────────────
/* Inline so the console has no CDN dependency — an icon set that fails to load on
   unfamiliar demo wifi is a worse trade than a few lines of SVG. */
const ICON = {
  spark: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z"/><path d="M20 2v4"/><path d="M22 4h-4"/><circle cx="4" cy="20" r="2"/></svg>`,
  lock:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 7 17l-5-5"/><path d="m22 10-7.5 7.5L13 16"/></svg>`,
};

function renderMoneyCards() {
  const t = totals();
  const pct = (v) => (t.cap ? Math.max(0, Math.min(100, (v / t.cap) * 100)) : 0);
  const card = (cls, label, value, note, icon) => {
    const fill = pct(value);
    return `
    <div class="card ${cls}">
      <div class="card-top">
        <div class="card-label">${label}</div>
        <div class="card-icon">${icon}</div>
      </div>
      <div class="card-value">${rupees(value)}<span class="card-pct">${fill.toFixed(1)}%</span></div>
      <div class="card-bar"><i style="width:${fill}%"></i></div>
      <div class="card-note">${note}</div>
    </div>`;
  };
  const n = state.approvals.length;
  el("money-cards").innerHTML =
    card("is-available", "Available to Spend", t.available, "Free budget across active agents", ICON.spark) +
    card("is-reserved",  "Reserved",           t.reserved,  "Held for pending approvals / execution", ICON.lock) +
    card("is-spent",     "Spent Today",        t.spent,     "Settled payments, rolling 24h", ICON.check) + `
    <div class="card is-pending">
      <div class="card-top">
        <div class="card-label">Awaiting Approval</div>
        <div class="card-icon">${n ? `<span class="card-ping"></span>` : ""}</div>
      </div>
      <div class="card-value">${n}<span class="card-pct">${n ? "Action needed" : "Clear"}</span></div>
      <div class="card-note">${n ? "Human decision required" : "Queue clear"}</div>
    </div>`;
}

// ── budget ───────────────────────────────────────────────────────────────────
function budgetMarkup(b, agentId) {
  const pct = (v) => (b.daily_cap ? (v / b.daily_cap) * 100 : 0);
  const free = Math.max(0, b.available);
  return `
    <div class="pad">
      ${agentId ? `<div class="subhead">${esc(agentId)}</div>` : ""}
      <div class="bar">
        <div class="bar-seg seg-spent" style="width:${pct(b.spent)}%">${pct(b.spent) > 12 ? "SPENT" : ""}</div>
        <div class="bar-seg seg-reserved" style="width:${pct(b.reserved)}%">${pct(b.reserved) > 12 ? "RESERVED" : ""}</div>
        <div class="bar-seg seg-free" style="width:${pct(free)}%">${pct(free) > 14 ? "AVAILABLE" : ""}</div>
      </div>
      <div class="legend">
        <div class="legend-item"><i class="swatch" style="background:var(--info)"></i>Spent ${rupees(b.spent)}</div>
        <div class="legend-item"><i class="swatch" style="background:var(--warn)"></i>Reserved ${rupees(b.reserved)}</div>
        <div class="legend-item"><i class="swatch" style="background:var(--ok)"></i>Available ${rupees(free)}</div>
      </div>
      <div style="margin-top:14px">
        <div class="kv"><span>Daily limit</span><b>${rupees(b.daily_cap)}</b></div>
        <div class="kv"><span>Spent</span><b>${rupees(b.spent)}</b></div>
        <div class="kv"><span>Reserved</span><b style="color:var(--warn)">${rupees(b.reserved)}</b></div>
        <div class="kv"><span>Available</span><b style="color:var(--ok)">${rupees(free)}</b></div>
      </div>
    </div>`;
}

function renderBudget() {
  const a = primaryAgent();
  const b = a && state.budgets[a.id];
  el("budget-body").innerHTML = b ? budgetMarkup(b) : `<div class="empty">No agent budget loaded</div>`;
  el("budget-full-body").innerHTML =
    state.agents.filter((x) => state.budgets[x.id]).map((x) => budgetMarkup(state.budgets[x.id], x.id)).join("") ||
    `<div class="empty">No active agents</div>`;
}

// ── pipeline ─────────────────────────────────────────────────────────────────
function renderPipeline() {
  const by = state.metrics?.by_state || {};
  const live = [
    ["Requested",     state.metrics?.processed ?? state.payments.length],
    ["Reserved",      by.RESERVED || 0],
    ["Approval",      by.PENDING_APPROVAL || 0],
    ["Executing",     by.EXECUTING || 0],
    ["Settled",       by.SETTLED || 0],
  ];
  const terms = [
    ["Blocked", by.BLOCKED || 0, "hot-err"],
    ["Failed",  by.FAILED || 0,  "hot-err"],
    ["Denied",  by.DENIED || 0,  "hot-err"],
    ["Unknown", by.UNKNOWN || 0, "hot-unknown"],
    ["Expired", by.EXPIRED || 0, "hot-ok"],
  ];
  el("pipeline-body").innerHTML = `
    <div class="pad">
      <div class="flow">
        ${live.map(([label, n]) => `
          <div class="flow-node ${n > 0 ? "lit" : ""}">
            <div class="flow-label">${label}</div>
            <div class="flow-count">${n}</div>
          </div>`).join("")}
      </div>
      <div class="subhead" style="margin:14px 0 0">Terminal states</div>
      <div class="flow-terminals">
        ${terms.map(([label, n, cls]) => `
          <div class="term ${n > 0 ? cls : ""}">
            <div class="flow-label">${label}</div>
            <div class="flow-count">${n}</div>
          </div>`).join("")}
      </div>
    </div>`;
}

// ── approvals ────────────────────────────────────────────────────────────────
/* The risk_reviewed entry is cached per payment. It used to be looked up in state.audit,
   which is only the last 100 entries, so on any sustained run the approval card silently
   lost its signal grid. /replay carries the payment's whole history. */
const reviewCache = {};
function signalsFor(pid) {
  const entry = state.audit.find((a) => a.payment_id === pid && a.event === "risk_reviewed");
  if (entry) {
    try { return (reviewCache[pid] = JSON.parse(entry.detail)); } catch { return null; }
  }
  if (!(pid in reviewCache)) {
    reviewCache[pid] = null;                      // placeholder: don't refetch every poll
    api.replay(pid).then((rep) => {
      const step = rep.steps.find((x) => x.event === "risk_reviewed");
      if (!step) return;
      try { reviewCache[pid] = JSON.parse(step.detail); renderApprovals(); } catch {}
    }).catch(() => {});
  }
  return reviewCache[pid];
}

function approvalMarkup(p) {
  const rev = signalsFor(p.id);
  const s = rev?.signals;
  const v = rev?.verdict;      // the deterministic rule: this is what decided
  const ai = rev?.advisory;    // the model's second opinion, if it was consulted
  const urgent = p.seconds_remaining < 120;

  const sig = (label, value, hot) => `
    <div class="signal ${hot ? "hot" : ""}">
      <div class="signal-k">${label}</div>
      <div class="signal-v">${value}</div>
    </div>`;

  return `
  <div class="approval">
    <div class="appr-top">
      <div>
        <div class="appr-amount">${rupees(p.amount)}</div>
        <div class="appr-meta">
          ${esc(p.merchant_id)} &nbsp;·&nbsp; ${esc(p.agent_id)} &nbsp;·&nbsp;
          invoice <span class="mono">${esc(p.invoice_ref)}</span>
        </div>
      </div>
      <div class="countdown ${urgent ? "urgent" : ""}" data-expires="${p.expires_at}">
        ${mmss(p.seconds_remaining)}<small>UNTIL AUTO-DENY</small>
      </div>
    </div>

    ${s ? `
    <div>
      <div class="subhead">Why was this escalated?</div>
      <div class="signals">
        ${sig("Amount", rupees(s.amount))}
        ${sig("Historical average", rupees(s.agent_avg_settled_amount))}
        ${sig("Amount / average", `${s.amount_ratio_to_average}×`, s.amount_ratio_to_average >= 3)}
        ${sig("First-time merchant", s.first_time_merchant ? "YES" : "no", s.first_time_merchant)}
        ${sig("Txns last hour", s.transactions_last_hour)}
        ${sig("History size", `${s.agent_settled_count} payments`)}
      </div>
    </div>` : `
    <div>
      <div class="subhead">Why was this escalated?</div>
      <div class="signal hot"><div class="signal-k">Policy rule</div><div class="signal-v" style="font-size:12px">${esc(p.reason)}</div></div>
    </div>`}

    ${v ? `
    <div class="ai-verdict">
      <div class="ai-line">
        <span class="subhead" style="margin:0">Policy rule</span>
        <span class="badge b-warn">${esc(String(v.decision).toUpperCase())}</span>
        <span class="badge b-info">DECIDED THIS</span>
      </div>
      <div class="ai-reason">${esc(v.reasoning)}</div>
    </div>` : ""}

    ${ai ? `
    <div class="ai-verdict">
      <div class="ai-line">
        <span class="subhead" style="margin:0">AI second opinion</span>
        <span class="badge b-muted">ADVISORY ONLY</span>
        ${ai.available === false
          ? `<span class="badge b-muted">ENGINE OFFLINE: FAILED CLOSED</span>`
          : ""}
      </div>
      <div class="ai-reason">${esc(ai.reasoning)}</div>
    </div>` : ""}

    <div class="appr-actions">
      <button class="btn btn-primary" data-approve="${p.id}" data-amount="${p.amount}">Approve Payment</button>
      <button class="btn btn-danger" data-deny="${p.id}" data-amount="${p.amount}">Deny Payment</button>
      <button class="btn btn-ghost" data-open="${p.id}">View decision path</button>
    </div>
  </div>`;
}

function renderApprovals() {
  const html = state.approvals.length
    ? `<div class="pad">${state.approvals.map(approvalMarkup).join("")}</div>`
    : `<div class="empty"><b>Queue clear</b>No payments are waiting on a human decision.</div>`;
  el("approvals-body").innerHTML = html;
  el("approvals-full-body").innerHTML = html;
}

// ── concurrency race ─────────────────────────────────────────────────────────
function renderRace() {
  const r = state.race;
  const lane = (name, res) => {
    const cls = !res ? "" : res.decision === "settled" ? "settled" : "blocked";
    return `
      <div class="lane ${cls} ${r?.firing ? "race-firing" : ""}">
        <div class="lane-name">${name}</div>
        <div class="lane-amt">${r ? rupees(r.amount) : "n/a"}</div>
        ${res ? stateBadge(res.state || (res.decision === "blocked" ? "BLOCKED" : "SETTLED"))
              : `<span class="badge b-muted">${r?.firing ? "IN FLIGHT" : "IDLE"}</span>`}
      </div>`;
  };
  el("race-body").innerHTML = `
    <div class="pad">
      <div class="race-lanes">
        ${lane("REQUEST A", r?.a)}
        ${lane("REQUEST B", r?.b)}
      </div>
      ${r && r.a && r.b ? `
        <div class="race-note settled-note">
          ${[r.a, r.b].filter((x) => x.decision === "settled").length} settled ·
          ${[r.a, r.b].filter((x) => x.decision !== "settled").length} blocked:
          ${esc([r.a, r.b].find((x) => x.decision !== "settled")?.reason || "budget protected")}
        </div>` : ""}
      <button class="btn btn-amber" id="btn-race" ${r?.firing ? "disabled" : ""} style="margin-top:10px">
        ${r?.firing ? "Dispatching…" : "Run concurrent race"}
      </button>
    </div>`;
  el("btn-race")?.addEventListener("click", () => runScenario("race"));
}

// ── reconciliation ───────────────────────────────────────────────────────────
function renderReconciliation() {
  const unknowns = state.payments.filter((p) => p.state === "UNKNOWN");
  el("reconcile-body").innerHTML = `
    <div class="pad">
      ${unknowns.length ? unknowns.map((p) => `
        <div class="recon-item">
          <div class="appr-top">
            <div>
              <div class="appr-amount" style="font-size:18px">${rupees(p.amount)}</div>
              <div class="appr-meta">${esc(p.merchant_id)} · <span class="mono">${short(p.id)}</span></div>
            </div>
            ${stateBadge("UNKNOWN")}
          </div>
          <div class="appr-meta" style="margin-top:8px">The payment rail timed out before confirming the outcome. The money stays reserved: it is neither counted as spent nor released.</div>
          <div class="recon-warn">DO NOT RETRY: OUTCOME UNCONFIRMED</div>
          <div class="recon-flow">
            <span class="step">EXECUTING</span><span class="arrow">→</span>
            <span class="step">TIMEOUT</span><span class="arrow">→</span>
            <span class="step">UNKNOWN</span><span class="arrow">→</span>
            <span class="step">QUERY ORIGINAL PAYMENT</span><span class="arrow">→</span>
            <span class="step">SETTLED / FAILED</span>
          </div>
        </div>`).join("") : `
        <div class="empty"><b>No unresolved payments</b>Every payment has a confirmed outcome.</div>`}
      <button class="btn ${unknowns.length ? "btn-amber" : ""}" id="btn-reconcile" style="margin-top:12px" ${unknowns.length ? "" : "disabled"}>
        Reconcile ${unknowns.length ? `(${unknowns.length})` : ""}
      </button>
    </div>`;

  el("btn-reconcile")?.addEventListener("click", async () => {
    try {
      const r = await api.reconcile();
      r.resolved.length
        ? toast("Reconciled", `${r.resolved.length} payment(s) resolved by querying the rail.`, "t-ok")
        : toast("Still unresolved", "The rail has not confirmed an outcome yet. The money stays held and the payment is not retried.", "t-warn");
      await refresh();
    } catch (e) { toast("Reconcile failed", e.message, "t-err"); }
  });
}

// ── payments table ───────────────────────────────────────────────────────────
function paymentsTable(rows) {
  if (!rows.length) return `<div class="empty"><b>No payments yet</b>Run a demo scenario to generate activity.</div>`;
  return `
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th>Payment</th><th style="text-align:right">Amount</th><th>Merchant</th>
        <th>Agent</th><th>Status</th><th>Risk</th><th>Created</th><th></th>
      </tr></thead>
      <tbody>
        ${rows.map((p) => `
          <tr class="clickable" data-open="${p.id}">
            <td class="tid">${short(p.id)}</td>
            <td class="num">${rupees(p.amount)}</td>
            <td>${esc(p.merchant_id)}</td>
            <td class="tid">${esc(p.agent_id)}</td>
            <td>${stateBadge(p.state)}</td>
            <td>${riskBadge(p)}</td>
            <td class="tid">${clockTime(p.created_at)}</td>
            <td><button class="btn btn-sm btn-ghost" data-open="${p.id}">Replay</button></td>
          </tr>`).join("")}
      </tbody>
    </table>
  </div>`;
}

function renderPayments() {
  el("payments-body").innerHTML = paymentsTable(state.payments);
  el("payments-overview-body").innerHTML = paymentsTable(state.payments.slice(0, 6));
}

// ── protection events ────────────────────────────────────────────────────────
const PROTECTION = {
  blocked:          ["Payment Blocked",          "b-err"],
  replayed:         ["Duplicate Payment Prevented", "b-info"],
  escalated:        ["Escalated for Human Review", "b-warn"],
  expired:          ["Approval Expired",          "b-muted"],
  denied:           ["Payment Denied",            "b-err"],
  unknown:          ["Rail Timeout",              "b-unknown"],
  reconciled:       ["Payment Reconciled",        "b-ok"],
  failed:           ["Payment Failed",            "b-err"],
  rejected:         ["Request Rejected",          "b-err"],
  approve_conflict: ["Late Decision Rejected",    "b-muted"],
  deny_conflict:    ["Late Decision Rejected",    "b-muted"],
};

function renderProtectionEvents() {
  const events = state.audit.filter((a) => PROTECTION[a.event]).slice(0, 8);
  el("protection-body").innerHTML = events.length ? `
    <div class="pad" style="display:grid;gap:8px">
      ${events.map((e) => {
        const [label, cls] = PROTECTION[e.event];
        return `
        <div class="signal" style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start">
          <div style="min-width:0">
            <div class="ai-line"><span class="badge ${cls}">${label}</span></div>
            <div class="tl-detail">${esc(e.detail || "n/a")}</div>
          </div>
          <div class="tl-time" style="white-space:nowrap">${clockTime(e.created_at)}</div>
        </div>`;
      }).join("")}
    </div>` : `<div class="empty"><b>No protection events</b>Blocks, escalations and reconciliations appear here.</div>`;
}

// ── metrics ──────────────────────────────────────────────────────────────────
function renderMetrics() {
  const m = state.metrics;
  if (!m || !el("metrics-body")) return;   // panel cut from the overview; metrics still power the pipeline
  const tile = (label, value, note) => `
    <div class="signal">
      <div class="signal-k">${label}</div>
      <div class="signal-v">${value}</div>
      ${note ? `<div class="card-note">${note}</div>` : ""}
    </div>`;
  el("metrics-body").innerHTML = `
    <div class="pad">
      <div class="signals">
        ${tile("Payments processed", m.processed)}
        ${tile("Blocked / failed", m.blocked)}
        ${tile("Escalated", m.escalated, `${m.escalation_rate}% escalation rate`)}
        ${tile("Approval rate", m.approval_rate === null ? "n/a" : `${m.approval_rate}%`)}
        ${tile("Budget overruns", m.budget_overruns,
               m.budget_overruns ? "LEDGER INVARIANT VIOLATED" : "ledger invariant holds")}
        ${tile("Reconciled", m.reconciled)}
        ${tile("Audit integrity", m.audit.intact ? "100%" : "FAILED", m.audit.intact ? `${m.audit.entries} entries verified` : "chain broken")}
        ${tile("Median approval time", m.median_approval_seconds === null ? "n/a" : mmss(m.median_approval_seconds))}
      </div>
    </div>`;
}

// ── audit ────────────────────────────────────────────────────────────────────
const ACTOR_BADGE = (actor) =>
  actor === "rule" ? `<span class="badge b-info">RULE</span>`
  : actor === "llm" ? `<span class="badge b-warn">AI</span>`
  : actor.startsWith("human:") ? `<span class="badge b-ok">HUMAN · ${esc(actor.slice(6))}</span>`
  : `<span class="badge b-muted">${esc(actor)}</span>`;

function renderAudit() {
  el("audit-body").innerHTML = state.audit.length ? `
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Time</th><th>Payment</th><th>Event</th><th>Actor</th><th>Reason</th><th>Integrity</th></tr></thead>
        <tbody>
          ${state.audit.map((a) => `
            <tr ${a.payment_id ? `class="clickable" data-open="${a.payment_id}"` : ""}>
              <td class="tid">${clockTime(a.created_at)}</td>
              <td class="tid">${a.payment_id ? short(a.payment_id) : "n/a"}</td>
              <td><span class="badge b-muted">${esc(a.event)}</span></td>
              <td>${ACTOR_BADGE(a.actor)}</td>
              <td class="muted" style="max-width:340px">${esc((a.detail || "").slice(0, 130))}</td>
              <td>${a.hash_valid ? `<span class="badge b-ok">VALID</span>` : `<span class="badge b-err">BROKEN</span>`}</td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>` : `<div class="empty"><b>Audit trail empty</b>Every decision will be recorded here.</div>`;
}

function renderIntegrity() {
  const v = state.metrics?.audit;
  el("integrity-body").innerHTML = `
    <div class="pad">
      <div class="appr-top">
        <div>
          <div class="ai-line">
            <span class="badge ${v?.intact ? "b-ok" : "b-err"}">${v?.intact ? "VERIFIED" : "INTEGRITY FAILURE"}</span>
          </div>
          <div class="appr-meta">${v?.intact
            ? `Hash chain integrity verified across ${v.entries} entries`
            : `Chain broken at entry ${esc(v?.broken_at)}: ${esc(v?.reason)}`}</div>
        </div>
        <button class="btn" id="btn-verify">Verify Audit Chain</button>
      </div>
    </div>`;
  el("btn-verify")?.addEventListener("click", async () => {
    const r = await api.verify();
    r.intact
      ? toast("Audit chain verified", `All ${r.entries} entries valid.`, "t-ok")
      : toast("Integrity failure", `Broken at entry ${r.broken_at}: ${r.reason}`, "t-err");
    await refresh();
  });
}

// ── rails ────────────────────────────────────────────────────────────────────
function renderRails() {
  const up = state.rails.filter((r) => r.status === "up");
  const cheapest = up.slice().sort((a, b) => a.fee_bps - b.fee_bps)[0];
  const labels = ["Primary rail", "Fallback rail", "Additional fallback"];
  const KIND = { sync: "SYNCHRONOUS", async: "ASYNC SETTLEMENT" };
  const ordered = state.rails.slice().sort((a, b) => a.fee_bps - b.fee_bps);

  el("rails-body").innerHTML = `
    <div class="pad">
      ${up.length === 0 ? `
        <div class="banner">
          <div class="banner-title">PAYMENT BLOCKED</div>
          <div class="banner-sub">No trusted payment rail is currently available. Reservations are released and no payment is sent. The firewall fails closed.</div>
        </div>` : ""}
      <div style="display:grid;gap:9px;margin-top:${up.length === 0 ? "14px" : "0"}">
        ${ordered.map((r, i) => `
          <div class="signal" style="display:flex;justify-content:space-between;align-items:center;gap:12px">
            <div>
              <div class="signal-k">${labels[i] || "Fallback"} &nbsp;·&nbsp; ${esc(r.label || "")}</div>
              <div class="ai-line" style="margin-top:5px">
                <span class="dot ${r.status === "up" ? "dot-ok" : "dot-err"}"></span>
                <b class="mono">${esc(r.name)}</b>
                <span class="badge ${r.status === "up" ? "b-ok" : "b-err"}">${r.status.toUpperCase()}</span>
                ${cheapest?.name === r.name ? `<span class="badge b-info">SELECTED</span>` : ""}
              </div>
              <div class="card-note">Fee ≈ ${(r.fee_bps / 100).toFixed(2)}% &nbsp;·&nbsp; ${KIND[r.kind] || ""}${
                r.kind === "async" ? ". An unconfirmed outcome here becomes UNKNOWN, never a retry" : ""}</div>
            </div>
            <button class="btn btn-sm" data-rail="${r.name}" data-status="${r.status === "up" ? "down" : "up"}">
              Take ${r.status === "up" ? "down" : "up"}
            </button>
          </div>`).join("")}
      </div>
      <div class="race-note" style="margin-top:12px">
        ${up.length === 0 ? "All rails unavailable. Payments fail closed."
          : `Routing to <b class="mono">${esc(cheapest.name)}</b> (cheapest available). If it goes down, the next-cheapest takes over automatically.`}
      </div>
    </div>`;

  el("rails-body").querySelectorAll("[data-rail]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api.setRail(b.dataset.rail, b.dataset.status);
        toast("Rail updated", `${b.dataset.rail} is now ${b.dataset.status}.`, "t-warn");
      } catch (e) {
        // The server refuses to bring up a rail it cannot send money to. Without this the
        // button just did nothing and the operator was left guessing.
        toast(`Cannot bring ${b.dataset.rail} up`, e.message, "t-err");
      }
      await refresh();
    })
  );
}

// ── drawer: payment detail + replay ──────────────────────────────────────────
const EVENT_COLOR = {
  settled: "var(--ok)", reconciled: "var(--ok)", approved: "var(--ok)",
  blocked: "var(--err)", failed: "var(--err)", denied: "var(--err)", rejected: "var(--err)",
  escalated: "var(--warn)", risk_reviewed: "var(--warn)",
  unknown: "var(--unknown)", expired: "var(--faint)",
};

async function openDrawer(pid) {
  el("drawer").hidden = false;
  el("drawer-scrim").hidden = false;
  el("drawer-id").textContent = pid;
  el("drawer-body").innerHTML = `<div class="empty">Loading decision path…</div>`;

  let rep;
  try { rep = await api.replay(pid); }
  catch { el("drawer-body").innerHTML = `<div class="empty">No record for this payment.</div>`; return; }

  const p = rep.current_state || {};
  el("drawer-title").textContent = `${rupees(p.amount || 0)} → ${p.merchant_id || "n/a"}`;

  el("drawer-body").innerHTML = `
    <div>
      <div class="section-title">Payment summary</div>
      <div class="kv"><span>State</span><b>${stateBadge(p.state)}</b></div>
      <div class="kv"><span>Amount</span><b>${rupees(p.amount || 0)} ${esc(p.currency || "")}</b></div>
      <div class="kv"><span>Merchant</span><b>${esc(p.merchant_id)}</b></div>
      <div class="kv"><span>Invoice</span><b>${esc(p.invoice_ref)}</b></div>
      <div class="kv"><span>Agent</span><b>${esc(p.agent_id)}</b></div>
      <div class="kv"><span>Rail</span><b>${esc(p.rail || "n/a")}</b></div>
      <div class="kv"><span>Created</span><b>${p.created_at ? clockTime(p.created_at) : "n/a"}</b></div>
      ${p.decided_by ? `<div class="kv"><span>Decided by</span><b>${esc(p.decided_by)}</b></div>` : ""}
    </div>

    <div>
      <div class="section-title">Decision path: replay</div>
      <div class="timeline">
        ${rep.steps.map((s) => `
          <div class="tl-item">
            <div class="tl-dot" style="background:${EVENT_COLOR[s.event] || "var(--info)"}"></div>
            <div class="tl-head">
              <span class="tl-event" style="color:${EVENT_COLOR[s.event] || "var(--info)"}">${esc(s.event)}</span>
              <span class="tl-time">${clockTime(s.created_at)}</span>
              ${ACTOR_BADGE(s.actor)}
              ${s.hash_valid ? "" : `<span class="badge b-err">HASH BROKEN</span>`}
            </div>
            ${s.detail ? `<div class="tl-detail">${esc(renderDetail(s))}</div>` : ""}
          </div>`).join("")}
      </div>
      <div class="race-note" style="margin-top:12px">
        Chain integrity for this payment:
        <b style="color:${rep.chain_intact ? "var(--ok)" : "var(--err)"}">${rep.chain_intact ? "VERIFIED" : "BROKEN"}</b>
      </div>
    </div>`;
}

/* risk_reviewed stores JSON; show its reasoning rather than a wall of serialised text */
function renderDetail(step) {
  if (step.event !== "risk_reviewed") return step.detail;
  try {
    const d = JSON.parse(step.detail);
    return `${String(d.verdict.decision).toUpperCase()}: ${d.verdict.reasoning}`;
  } catch { return step.detail; }
}

function closeDrawer() {
  el("drawer").hidden = true;
  el("drawer-scrim").hidden = true;
}

// ── approve / deny modal ─────────────────────────────────────────────────────
let pendingDecision = null;

function askReason(pid, action, amount) {
  pendingDecision = { pid, action };
  el("modal-title").textContent = action === "approve" ? "Approve Payment" : "Deny Payment";
  el("modal-sub").innerHTML =
    action === "approve"
      ? `You are approving <b>${rupees(amount)}</b> over an active risk escalation. A reason is required and recorded against your name.`
      : `You are denying <b>${rupees(amount)}</b>. The reservation is released back to available budget.`;
  el("modal-confirm").className = `btn ${action === "approve" ? "btn-primary" : "btn-danger"}`;
  el("modal-confirm").textContent = action === "approve" ? "Confirm Approval" : "Confirm Denial";
  el("modal-reason").value = "";
  el("modal-scrim").hidden = false;
  el("modal-reason").focus();
}

async function submitDecision() {
  const reason = el("modal-reason").value.trim();
  if (!reason) { toast("Reason required", "Every override is recorded in the audit trail.", "t-warn"); return; }
  const { pid, action } = pendingDecision;
  el("modal-scrim").hidden = true;
  try {
    const r = await api.decide(pid, action, OPERATOR, reason);
    toast(action === "approve" ? "Payment approved" : "Payment denied", r.reason || "", action === "approve" ? "t-ok" : "t-warn");
  } catch (e) {
    e.status === 409
      ? toast("Already resolved", "This payment was decided or expired first. Your decision came too late.", "t-err")
      : toast("Decision failed", e.message, "t-err");
  }
  await refresh();
}

// ── demo scenarios (real API calls; trigger amounts never rendered) ───────────
// Signing secrets come from the loopback-only /demo/keys; none ship in this file.
const OPS = "ops-agent", RACE = "race-agent";
const SECRETS = {};
const ACME = { merchant_id: "acme-supplies", currency: "INR", payout_account: "ACME-ACC-001" };
const CLOUD = { merchant_id: "cloudify", currency: "INR", payout_account: "CLD-ACC-77" };
const TIMEOUT_AMOUNT = 130000, FAIL_AMOUNT = 170000, RACE_AMOUNT = 300000;
const uniq = () => Math.random().toString(36).slice(2, 8);
const log = (m) => { el("dock-log").textContent = m; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* Step banner: the narration card that leads each demo step. Its bar drains across
   `secs`, so the corner is visibly counting down rather than frozen, and the result
   toast lands underneath it while it is still on screen. */
function stepBanner(label, text, secs) {
  const node = document.createElement("div");
  node.className = "toast t-step";
  node.innerHTML = `<b>${esc(label)}</b><div class="step-text">${esc(text)}</div>` +
                   `<div class="tbar"><i style="animation-duration:${secs}s"></i></div>`;
  el("toasts").appendChild(node);
  setTimeout(() => node.remove(), secs * 1000);
}

/* A scenario may only claim success when it actually produced the decision it advertises.
   Anything else reports what really happened — a green toast over a failed run is worse
   than no toast at all. */
const outcome = (r, expected, title, msg, kind = "t-ok") =>
  r?.decision === expected
    ? toast(title, msg, kind)
    : toast(`Unexpected result: ${r?.decision ?? "error"}`, r?.reason || "", "t-err");

const SCENARIOS = [
  { id: "mcp", name: "Agent over MCP", note: "a real MCP client", async run() {
      // A browser cannot launch a stdio MCP server, so the firewall runs the same script an
      // operator would run in a second terminal. One request per tool call, narrated here,
      // so each payment lands in the tables while the room is still reading why it was made.
      let hello;
      try {
        hello = await api.mcpStep(-1);
      } catch (e) {
        log(`MCP session failed: ${e.message}`);
        toast("MCP session failed", e.message, "t-err");
        return;
      }
      stepBanner("An agent is connecting over MCP",
                 `Connected to ${hello.server}. Tools offered: ${hello.tools.join(", ")}.`, 6);
      log(`Connected to ${hello.server} · ${hello.tools.join(", ")}`);
      await sleep(4000);

      for (let n = 0, step = null; !step?.last; n++) {
        step = await api.mcpStep(n);
        stepBanner(`Step ${n + 1}`, step.narration, 7);
        log(`${n + 1}: ${step.narration}`);
        await sleep(2200);
        await refresh();
        // The firewall answers "VERDICT: sentence" for a payment and plain text for a read.
        // The verdict always comes from the response, never from the script.
        const head = step.result.split("\n")[0];
        const m = head.match(/^([A-Z]+):\s*(.*)$/);
        const why = (step.result.match(/^reason:\s*(.+)$/m) || [])[1];
        const detail = [m ? m[2] : head, m && why ? why : ""].join(" ").trim();
        toast(`${n + 1} · ${m ? m[1] : `agent called ${step.tool}`}`, detail,
              /^(BLOCKED|PENDING|REFUSED|FAILED|RECONCILING)$/.test(m?.[1]) ? "t-warn" : "t-ok");
        log(`${n + 1} → ${detail}`);
        await sleep(3500);
      }
      toast("The agent asked. It never decided.",
            "Every one of those calls came in over MCP and went through the same policy, ledger and audit chain as any other payment.",
            "t-ok");
  }},
  { id: "clean", name: "Clean payment", note: "settles end-to-end", async run() {
      log("Submitting a routine payment…");
      const r = await api.pay(OPS, { ...ACME, invoice_ref: `inv-${uniq()}`, amount: 40000 });
      log(`→ ${r.decision.toUpperCase()} ${r.rail ? `via ${r.rail}` : ""}`);
      outcome(r, "settled", "Payment settled", `Routed via ${r.rail || "n/a"}.`);
  }},
  { id: "duplicate", name: "Duplicate invoice", note: "same invoice twice", async run() {
      const invoice_ref = `inv-${uniq()}`;
      log("Sending the same invoice twice…");
      await api.pay(OPS, { ...ACME, invoice_ref, amount: 35000 });
      const second = await api.pay(OPS, { ...ACME, invoice_ref, amount: 35000 });
      log(`→ second attempt: ${second.decision.toUpperCase()}`);
      outcome(second, "replayed", "Duplicate prevented",
              "The retry replayed the original result instead of paying twice.");
  }},
  { id: "velocity", name: "Velocity / structuring", note: "split payments", async run() {
      log("Splitting one large payment into smaller ones…");
      let last;
      for (let i = 0; i < 3; i++) {
        last = await api.pay(OPS, { ...ACME, invoice_ref: `inv-${uniq()}`, amount: 60000 });
        log(`→ payment ${i + 1}: ${last.decision.toUpperCase()}`);
        await refresh();
      }
      outcome(last, "blocked", "Structuring blocked",
              "Each payment passed alone; the rolling window caught the pattern.", "t-warn");
  }},
  { id: "race", agent: "race-agent", name: "Concurrent budget race", note: "two at once", async run() {
      state.race = { amount: RACE_AMOUNT, firing: true, a: null, b: null };
      renderRace();
      log("Dispatching two payments simultaneously…");
      // The race itself resolves in ~40ms — far too fast to watch. Hold the IN FLIGHT
      // state briefly so the lanes are visibly in flight before the result lands.
      await sleep(900);
      const [a, b] = await Promise.all([
        api.pay(RACE, { ...ACME, invoice_ref: `race-a-${uniq()}`, amount: RACE_AMOUNT }).catch((e) => e.body),
        api.pay(RACE, { ...CLOUD, invoice_ref: `race-b-${uniq()}`, amount: RACE_AMOUNT }).catch((e) => e.body),
      ]);
      state.race = { amount: RACE_AMOUNT, firing: false, a, b };
      renderRace();
      const settled = [a, b].filter((x) => x?.decision === "settled").length;
      log(`→ ${settled} settled, ${2 - settled} blocked`);
      settled === 1
        ? toast("Budget protected", "Two simultaneous requests could not spend the same budget.", "t-ok")
        : toast(`Unexpected: ${settled} of 2 settled`, "Exactly one should win the reservation.", "t-err");
  }},
  { id: "escalation", name: "Risk escalation", note: "unusual payment", async run() {
      log("Building a settlement baseline…");
      for (let i = 0; i < 3; i++) await api.pay(OPS, { ...ACME, invoice_ref: `base-${uniq()}`, amount: 10000 });
      await refresh();
      log("Submitting an unusual payment to a first-time merchant…");
      toast("Reviewing", "Comparing the amount against this agent's own settled history…", "t-step");
      const r = await api.pay(OPS, { ...CLOUD, invoice_ref: `inv-${uniq()}`, amount: 80000 });
      log(`→ ${r.decision.toUpperCase()}`);
      outcome(r, "pending", "Escalated to human",
              "A deterministic rule paused it. The model only annotates it.", "t-warn");
  }},
  { id: "timeout", agent: "race-agent", name: "Rail timeout → unknown", note: "then reconcile", async run() {
      log("Submitting a payment whose rail will time out…");
      const r = await api.pay(RACE, { ...ACME, invoice_ref: `inv-${uniq()}`, amount: TIMEOUT_AMOUNT });
      log(`→ ${r.decision.toUpperCase()}: awaiting reconciliation`);
      outcome(r, "reconciling", "Outcome unconfirmed",
              "The rail timed out. The payment is UNKNOWN and will not be retried.", "t-warn");
  }},
  { id: "allrails", name: "All rails down", note: "fails closed", async run() {
      // Straight from the server, not state.rails: nothing refreshes between the reset and
      // here, so the cached copy can be a scenario out of date and this would restore it.
      const before = (await api.rails()).map((r) => [r.name, r.status]);
      try {
        log("Taking every payment rail offline…");
        for (const [name] of before) await api.setRail(name, "down");
        await refresh();
        const r = await api.pay(OPS, { ...ACME, invoice_ref: `inv-${uniq()}`, amount: 25000 });
        log(`→ ${r.decision.toUpperCase()}: no payment sent`);
        outcome(r, "failed", "Failed closed",
                "No rail available, so nothing was sent and the reservation was released.", "t-err");
        await sleep(4000);
      } finally {
        // Put back exactly what this scenario switched off, whatever happened in between.
        // Nothing else restores rails now, so leaving them down here makes every later
        // scenario fail closed for a reason nobody in the room can see.
        for (const [name, status] of before) await api.setRail(name, status);
      }
  }},
  { id: "runaway", name: "Runaway agent", note: "loop, then throttled", async run() {
      // A looping agent is the realistic version of "the AI went wrong": not one bad
      // payment but the same call forever. Rs.1 each, so no cap fires first and the only
      // thing that stops it is the rate limiter.
      log("An agent stuck in a loop starts firing payments…");
      let accepted = 0, refused = 0, throttled = 0;
      const fire = async () => {
        try {
          const r = await api.pay(OPS, { ...ACME, invoice_ref: `loop-${uniq()}`, amount: 100 });
          r.decision === "settled" ? accepted++ : refused++;
        } catch (e) {
          e.status === 429 ? throttled++ : refused++;
        }
      };
      // In parallel, because that is what a looping agent actually does, and because 75
      // sequential signed requests take 26 seconds.
      for (let batch = 0; batch < 5; batch++) {
        await Promise.all(Array.from({ length: 15 }, fire));
        log(`… ${(batch + 1) * 15} sent, ${accepted} through, ${throttled} throttled`);
      }
      log(`→ ${accepted} accepted, ${refused} refused, ${throttled} rate-limited`);
      throttled > 0
        ? toast("Runaway agent throttled",
                `${accepted} payments went through, then ${throttled} requests were refused ` +
                `before they reached the ledger.`, "t-warn")
        : toast("Not throttled", `${accepted} accepted, ${refused} refused, 0 rate-limited.`, "t-err");
  }},
  { id: "fullday", agent: "race-agent", name: "Run a full day", note: "~60s, narrated", async run() {
      // One agent, six payments, no reset in between — the only scenario where the money
      // accumulates. Paced at ~10s per step so a room can follow the story instead of
      // watching six payments finish in 200ms.
      const first = `day-${uniq()}`;
      const day = [
        { say: "A routine invoice arrives from a supplier this agent has paid before.",
          intent: { ...ACME, invoice_ref: first, amount: 150000 },
          expect: "settled", kind: "t-ok",
          story: "₹1,500 reserved, routed to the cheapest rail, settled. Reserved becomes spent." },
        { say: "Next invoice. This one's rail is about to stop responding.",
          intent: { ...ACME, invoice_ref: `day-${uniq()}`, amount: TIMEOUT_AMOUNT },
          expect: "reconciling", kind: "t-warn",
          story: "The rail timed out. Nobody knows whether the money moved, so it stays held, and nothing is resent." },
        { say: "A third invoice: same supplier, but the payout account has changed.",
          intent: { ...ACME, invoice_ref: `day-${uniq()}`, amount: 80000,
                    payout_account: `WRONG-ACC-${uniq()}` },
          expect: "pending", kind: "t-warn",
          story: "Whitelisted merchant, unrecognised bank account. Held for a human. The money is locked, not sent." },
        { say: "The agent resends its very first invoice, a hiccup on its side.",
          intent: { ...ACME, invoice_ref: first, amount: 150000 },
          expect: "replayed", kind: "t-ok",
          story: "Same invoice, same amount. The original result is replayed. The supplier is not paid twice." },
        { say: "Another ordinary invoice. The day's budget is filling up.",
          intent: { ...ACME, invoice_ref: `day-${uniq()}`, amount: 100000 },
          expect: "settled", kind: "t-ok",
          story: "Settled. Between spent and held, most of the daily cap is now committed." },
        { say: "One last invoice: small, ordinary, and it will not go through.",
          intent: { ...ACME, invoice_ref: `day-${uniq()}`, amount: 50000 },
          expect: "blocked", kind: "t-warn",
          story: "Refused. Spent plus held already reaches the cap, including the payment nobody can confirm yet." },
      ];
      let last, n = 0;
      for (const step of day) {
        n++;
        // Banner first, for the whole 10s beat; the result toast appears under it.
        stepBanner(`Step ${n} of ${day.length}`, step.say, 7);
        log(`${n}/${day.length}: ${step.say}`);
        await sleep(2200);
        last = await api.pay(RACE, step.intent);
        await refresh();
        // The title always carries the real decision; the scripted line is only shown
        // when the step actually did what it says it does.
        const ok = last.decision === step.expect;
        toast(`${n}/${day.length} · ${last.decision.toUpperCase()}`,
              ok ? step.story : last.reason || "", ok ? step.kind : "t-err");
        log(`${n}/${day.length} → ${last.decision.toUpperCase()} · ${ok ? step.story : last.reason}`);
        await sleep(3500);
      }
      outcome(last, "blocked", "Day complete",
              "Spent, held and available are all on screen, including money held for an outcome nobody has confirmed.",
              "t-warn");
  }},
];

let running = false;
async function runScenario(id) {
  if (running) return;
  running = true;
  document.querySelectorAll(".scenario").forEach((b) => (b.disabled = true));
  try {
    // Every scenario starts from a clean ledger. Without this, an earlier scenario's
    // spend eats the agent's velocity cap and the next one blocks for the wrong reason.
    log("Resetting demo state…");
    await api.reset(true);
    state.race = null;
    const scenario = SCENARIOS.find((s) => s.id === id);
    state.focusAgent = scenario.agent || "ops-agent";
    await scenario.run();
  } catch (e) {
    log(`Error: ${e.message}`);
    toast("Scenario error", e.message, "t-err");
  } finally {
    running = false;
    document.querySelectorAll(".scenario").forEach((b) => (b.disabled = false));
    await refresh();
  }
}

function renderScenarios() {
  el("scenario-list").innerHTML = SCENARIOS.map((s) => `
    <button class="scenario" data-scenario="${s.id}">
      <span>${s.name}</span><small>${s.note}</small>
    </button>`).join("");
  el("scenario-list").querySelectorAll("[data-scenario]").forEach((b) =>
    b.addEventListener("click", () => runScenario(b.dataset.scenario))
  );
}

// ── countdown ticker (local, so timers move between polls) ───────────────────
function tickCountdowns() {
  const now = Math.floor(Date.now() / 1000);
  document.querySelectorAll(".countdown[data-expires]").forEach((node) => {
    const left = Math.max(0, +node.dataset.expires - now);
    node.classList.toggle("urgent", left < 120);
    node.firstChild.textContent = mmss(left) + " ";
  });
  el("clock").textContent = new Date().toLocaleTimeString("en-IN", { hour12: false });
}

// ── wiring ───────────────────────────────────────────────────────────────────
el("nav").addEventListener("click", (e) => {
  const btn = e.target.closest(".nav-item");
  if (!btn) return;
  state.view = btn.dataset.view;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b === btn));
  document.querySelectorAll(".view").forEach((v) => (v.hidden = v.dataset.view !== state.view));
});

document.addEventListener("click", (e) => {
  const open = e.target.closest("[data-open]");
  if (open) { openDrawer(open.dataset.open); return; }
  const ap = e.target.closest("[data-approve]");
  if (ap) { askReason(ap.dataset.approve, "approve", +ap.dataset.amount); return; }
  const dn = e.target.closest("[data-deny]");
  if (dn) { askReason(dn.dataset.deny, "deny", +dn.dataset.amount); return; }
});

el("drawer-close").addEventListener("click", closeDrawer);
el("drawer-scrim").addEventListener("click", closeDrawer);
el("modal-cancel").addEventListener("click", () => (el("modal-scrim").hidden = true));
el("modal-confirm").addEventListener("click", submitDecision);
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  // Modal sits above the drawer, so Escape dismisses the topmost layer only.
  if (!el("modal-scrim").hidden) { el("modal-scrim").hidden = true; return; }
  closeDrawer();
});

el("btn-show-audit").addEventListener("click", (e) => {
  const body = el("audit-body");
  body.hidden = !body.hidden;
  e.target.textContent = body.hidden ? "Show Audit Trail" : "Hide Audit Trail";
});
el("dock-toggle").addEventListener("click", () => {
  const body = el("dock-body");
  body.hidden = !body.hidden;
  // The label is the only exit affordance, so it has to name the action, not the mode.
  el("dock-toggle-label").textContent = body.hidden ? "Demo Mode" : "Close Demo Panel";
  el("dock-toggle").setAttribute("aria-expanded", String(!body.hidden));
});
el("btn-reset").addEventListener("click", async () => {
  await api.reset();
  state.race = null;
  log("Demo state cleared.");
  toast("Demo reset", "Payment and audit history cleared; rails restored.", "t-ok");
  await refresh();
});

renderScenarios();
api.demoKeys()
  .then((k) => Object.assign(SECRETS, k))
  .catch(() => log("Signing secrets unavailable. Scenarios are disabled off-host."));
refresh();
setInterval(refresh, 2500);
setInterval(tickCountdowns, 1000);

// -- sidebar collapse ---------------------------------------------------------
(() => {
  const sidebar = el("sidebar"), toggle = el("sidebar-toggle");
  if (!sidebar || !toggle) return;

  // Collapsed, the nav is icons only — so each item needs a name that survives its
  // label being display:none, for both a tooltip and a screen reader.
  document.querySelectorAll(".nav-item").forEach((b) => {
    const label = b.querySelector(".nav-left span")?.textContent.trim();
    if (label) { b.title = label; b.setAttribute("aria-label", label); }
  });

  const apply = (collapsed) => {
    sidebar.classList.toggle("collapsed", collapsed);
    toggle.setAttribute("aria-expanded", String(!collapsed));
    const verb = collapsed ? "Expand" : "Collapse";
    toggle.setAttribute("aria-label", `${verb} sidebar`);
    toggle.title = `${verb} sidebar`;
  };

  let collapsed = localStorage.getItem("sidebar") === "collapsed";
  apply(collapsed);
  toggle.addEventListener("click", () => {
    collapsed = !collapsed;
    localStorage.setItem("sidebar", collapsed ? "collapsed" : "open");
    apply(collapsed);
  });
})();

// -- theme toggle -------------------------------------------------------------
(() => {
  const toggle = el('theme-toggle');
  const icon = el('theme-icon');
  const applyTheme = (isDark) => {
    document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
    if (icon) {
      icon.innerHTML = isDark
        ? '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>'
        : '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
    }
  };
  const stored = localStorage.getItem('theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  let currentIsDark = stored === 'dark' || (!stored && prefersDark);
  applyTheme(currentIsDark);

  if (toggle) {
    toggle.addEventListener('click', () => {
      currentIsDark = !currentIsDark;
      localStorage.setItem('theme', currentIsDark ? 'dark' : 'light');
      applyTheme(currentIsDark);
    });
  }
})();
