/* ============================================================
   SOC Sentinel — browser GUI logic
   ============================================================ */

// ── State ───────────────────────────────────────────────────
const state = {
  tab: "query",
  config: null,
  hits: [],              // results from the last query
  query: "",
  time: "",
  filter: "",
  enrichment: {},        // { ip: {data} | {error} }
  analyses: [],          // [{hit, analysis, description_text, timestamp}]
  tickets: [],           // [{ticket, result}]
  pendingTicket: null,   // ticket currently being drafted
};

// ── DOM helpers ─────────────────────────────────────────────
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") {
      node.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (v === true) node.setAttribute(k, "");
    else if (v === false || v == null) {} // skip
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// ── Toasts ───────────────────────────────────────────────────
function toast(msg, { type = "info", title = "", timeout = 4200 } = {}) {
  const root = $("#toasts");
  const t = el("div", { class: `toast ${type}` },
    title ? el("div", { class: "title" }, title) : null,
    el("div", { class: "body" }, msg),
  );
  root.appendChild(t);
  setTimeout(() => t.remove(), timeout);
}

// ── Theme ────────────────────────────────────────────────────
function initTheme() {
  const saved = localStorage.getItem("soc-theme");
  if (saved === "light" || saved === "dark") {
    document.documentElement.dataset.theme = saved;
  }
  $("#theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("soc-theme", next);
  });
}

// ── Tabs ────────────────────────────────────────────────────
const TAB_TITLES = {
  query:      ["Search Alerts",    "Query OpenSearch for Suricata alerts"],
  alerts:     ["Alerts",           "Results from the latest query"],
  enrichment: ["IP Enrichment",    "AbuseIPDB reputation for public source IPs"],
  analysis:   ["AI Analysis",      "Gemini-generated incident reports"],
  tickets:    ["Tickets",          "Draft & submit MantisBT issues"],
  manual:     ["User Manual",      "How to use every feature of SOC Sentinel"],
};

function switchTab(name) {
  if (!TAB_TITLES[name]) return;
  state.tab = name;
  $$(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  const [title, sub] = TAB_TITLES[name];
  $("#tab-title").textContent = title;
  $("#tab-sub").textContent = sub;
}

// ── API ─────────────────────────────────────────────────────
async function api(path, { method = "GET", body = null } = {}) {
  const opts = { method, headers: {} };
  if (body !== null) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  let data = null;
  try { data = await resp.json(); } catch (_) { data = null; }
  if (!resp.ok || (data && data.ok === false)) {
    const err = (data && data.error) || `${resp.status} ${resp.statusText}`;
    const e = new Error(err);
    e.payload = data;
    throw e;
  }
  return data;
}

// ── Config / secrets status ─────────────────────────────────
async function loadConfig() {
  try {
    state.config = await api("/api/config");
  } catch (e) {
    toast(`Failed to load config: ${e.message}`, { type: "error" });
    return;
  }

  // Connection chip
  const base = state.config.opensearch.base_url;
  const tr = state.config.opensearch.transport;
  $("#connection-chip").textContent = `OpenSearch • ${tr} • ${base}`;

  // Secret dots
  const dots = $("#secret-status");
  dots.innerHTML = "";
  const labels = {
    opensearch: "OpenSearch",
    abuseipdb: "AbuseIPDB",
    gemini: "Gemini",
    mantis: "Mantis",
  };
  for (const [k, present] of Object.entries(state.config.secrets)) {
    dots.appendChild(el("span", {
      class: `secret-dot ${present ? "ok" : "missing"}`,
      title: present ? `${labels[k]} credentials present` : `${labels[k]} credentials missing`,
    }, labels[k]));
  }

  // Examples list
  const list = $("#examples-list");
  list.innerHTML = "";
  for (const ex of state.config.example_queries) {
    const li = el("li", {
      class: "example-item",
      onclick: () => {
        $("#q-query").value = ex.query;
        $("#q-query").focus();
        toast("Loaded example query", { type: "info", timeout: 1500 });
      },
    },
      el("code", {}, ex.query),
      el("div", { class: "example-desc" }, ex.description),
    );
    list.appendChild(li);
  }
}

// ── Query form ──────────────────────────────────────────────
function initQueryForm() {
  const timeSel = $("#q-time");
  const customWrap = $("#q-custom-wrap");
  timeSel.addEventListener("change", () => {
    customWrap.hidden = timeSel.value !== "__custom__";
  });

  $("#reset-btn").addEventListener("click", () => {
    $("#q-query").value = window.SOC_DEFAULTS.query;
    $("#q-size").value = window.SOC_DEFAULTS.size;
    $("#q-time").value = "now-48h";
    customWrap.hidden = true;
  });

  $("#query-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    await runQuery();
  });
}

function resolveTimeValue() {
  const v = $("#q-time").value;
  if (v === "__custom__") {
    let c = $("#q-custom").value.trim() || "2h";
    c = c.replace(/^now-/, "");
    return `now-${c}`;
  }
  return v;
}

async function runQuery() {
  const query = $("#q-query").value.trim() || window.SOC_DEFAULTS.query;
  const size = parseInt($("#q-size").value, 10) || window.SOC_DEFAULTS.size;
  const time = resolveTimeValue();

  const btn = $("#run-btn");
  const spinner = $(".spinner", btn);
  btn.disabled = true;
  spinner.hidden = false;
  $(".btn-label", btn).textContent = "Running…";

  try {
    const data = await api("/api/query", {
      method: "POST",
      body: { query, size, time },
    });
    state.hits = data.hits || [];
    state.query = data.query;
    state.time = data.time;
    state.filter = "";
    $("#alerts-filter").value = "";

    renderAlerts();
    $("#badge-alerts").hidden = state.hits.length === 0;
    $("#badge-alerts").textContent = state.hits.length;

    toast(`${data.count} alert${data.count === 1 ? "" : "s"} returned`,
      { type: "success", title: "Query complete" });

    switchTab("alerts");
  } catch (e) {
    toast(e.message, { type: "error", title: "Query failed" });
    if (e.payload && e.payload.missing_secret) {
      toast(`Add secrets/${e.payload.missing_secret === "opensearch" ? "wa_opensearch.json" : e.payload.missing_secret + ".json"}`,
        { type: "warning" });
    }
  } finally {
    btn.disabled = false;
    spinner.hidden = true;
    $(".btn-label", btn).textContent = "Run query";
  }
}

// ── Alerts rendering ────────────────────────────────────────
function sevClass(sev) {
  if (sev == null) return "sev-none";
  const n = parseInt(sev, 10);
  if (n <= 1) return "sev-1";
  if (n === 2) return "sev-2";
  return "sev-3";
}
function sevLabel(sev) {
  if (sev == null) return "Sev —";
  return `Sev ${sev}`;
}

function renderAlerts() {
  const list = $("#alerts-list");
  list.innerHTML = "";

  const filtered = state.hits.filter(h => matchesFilter(h, state.filter));

  $("#alerts-count-chip").textContent =
    `${filtered.length} / ${state.hits.length} alert${state.hits.length === 1 ? "" : "s"}`;
  $("#alerts-time-chip").textContent = state.time ? `${state.time} → now` : "";
  $("#alerts-time-chip").hidden = !state.time;
  $("#alerts-query-chip").textContent = state.query ? `q: ${state.query}` : "";
  $("#alerts-query-chip").hidden = !state.query;

  $("#enrich-all-btn").disabled = state.hits.filter(h => h.src_is_public).length === 0;

  if (!state.hits.length) {
    list.appendChild(el("div", { class: "empty" },
      el("div", { class: "empty-icon" }, "🔍"),
      el("div", { class: "empty-title" }, "No results yet"),
      el("div", { class: "muted" }, "Head to Search to run a query."),
    ));
    return;
  }

  if (!filtered.length) {
    list.appendChild(el("div", { class: "empty" },
      el("div", { class: "empty-icon" }, "🕵️"),
      el("div", { class: "empty-title" }, "No alerts match the filter"),
      el("div", { class: "muted" }, `No alert contains “${state.filter}”.`),
    ));
    return;
  }

  for (const hit of filtered) list.appendChild(alertCard(hit));
}

function matchesFilter(h, f) {
  if (!f) return true;
  const needle = f.toLowerCase();
  const hay = [
    h.signature, h.category, h.src_ip, h.dest_ip,
    h.src_port, h.dest_port, h.proto, h.app_proto,
    h.hostname, h.node, h.src_country, h.dest_country,
    h.signature_id, h.flow_id, h.community_id,
  ].filter(v => v != null).join(" ").toLowerCase();
  return hay.includes(needle);
}

function alertCard(h) {
  const card = el("article", {
    class: `alert-card ${sevClass(h.severity)}`,
    dataset: { idx: h.idx },
  });

  // Head
  const flow = el("span", { class: "flow-line" },
    el("span", { class: "ip" }, `${h.src_ip || "?"}:${h.src_port ?? "?"}`),
    el("span", { class: "arrow" }, "→"),
    h.proto && el("span", { class: "proto" }, `${h.proto}${h.app_proto ? "/" + h.app_proto : ""}`),
    el("span", { class: "ip" }, `${h.dest_ip || "?"}:${h.dest_port ?? "?"}`),
  );

  const meta = el("div", { class: "alert-meta" },
    h.timestamp ? `${h.timestamp}` : "—",
    h.category ? ` • ${h.category}` : "",
    h.src_country ? ` • src: ${h.src_country}` : "",
    h.dest_country ? ` • dst: ${h.dest_country}` : "",
  );

  const head = el("div", { class: "alert-head",
    onclick: () => card.classList.toggle("open"),
    oncontextmenu: (e) => { e.preventDefault(); card.classList.toggle("open"); },
  },
    el("span", { class: "sev-pill" }, sevLabel(h.severity)),
    el("div", {},
      el("div", { class: "alert-title" }, h.signature || "(no signature)"),
      flow,
      meta,
    ),
    el("div", { class: "muted mono", style: "font-size:12px" }, `#${h.idx}`),
  );

  // Body
  const body = el("div", { class: "alert-body" });

  const fields = [
    ["Timestamp",      h.timestamp],
    ["Signature ID",   h.signature_id],
    ["Category",       h.category],
    ["Protocol",       [h.proto, h.app_proto].filter(Boolean).join(" / ") || null],
    ["Source IP:port", h.src_ip ? `${h.src_ip}:${h.src_port ?? "?"}` : null],
    ["Source GeoIP",   [h.src_country, h.src_city].filter(Boolean).join(", ") || null],
    ["Source ASN",     h.src_asn],
    ["Destination",    h.dest_ip ? `${h.dest_ip}:${h.dest_port ?? "?"}` : null],
    ["Dest GeoIP",     h.dest_country],
    ["Packets →",      h.pkts_to],
    ["Packets ←",      h.pkts_from],
    ["Bytes →",        h.bytes_to_h],
    ["Bytes ←",        h.bytes_from_h],
    ["Flow ID",        h.flow_id],
    ["Community ID",   h.community_id],
    ["Host",           h.hostname],
    ["Node",           h.node],
    ["Index",          h.doc_index],
    ["Document ID",    h.doc_id],
  ].filter(([, v]) => v !== null && v !== undefined && v !== "");

  const grid = el("div", { class: "siem-grid" });
  for (const [k, v] of fields) {
    grid.appendChild(el("div", { class: "siem-field" },
      el("div", { class: "k" }, k),
      el("div", { class: "v" }, String(v)),
    ));
  }
  body.appendChild(grid);

  // Actions
  const actions = el("div", { class: "alert-actions" });
  if (h.src_is_public) {
    actions.appendChild(el("button", {
      class: "btn btn-secondary btn-sm",
      onclick: () => enrichIps([h.src_ip], { focus: true }),
    }, "🌐 Enrich source IP"));
  }
  actions.appendChild(el("button", {
    class: "btn btn-secondary btn-sm",
    onclick: () => showRawJson(h),
  }, "🧾 View raw JSON"));

  if (h.message) {
    actions.appendChild(el("button", {
      class: "btn btn-primary btn-sm",
      onclick: () => analyzeHit(h),
    }, "🤖 AI analyze"));
  }

  if (h.discover_url) {
    actions.appendChild(el("a", {
      class: "btn btn-ghost btn-sm",
      href: h.discover_url,
      target: "_blank",
      rel: "noopener",
    }, "↗ Open in Discover"));
  }

  actions.appendChild(el("button", {
    class: "btn btn-ghost btn-sm",
    onclick: async () => {
      try { await navigator.clipboard.writeText(JSON.stringify(h, null, 2)); toast("Copied to clipboard", { type: "success", timeout: 1500 }); }
      catch { toast("Copy failed", { type: "error" }); }
    },
  }, "📋 Copy"));

  body.appendChild(actions);
  card.appendChild(head);
  card.appendChild(body);
  return card;
}

function showRawJson(h) {
  $("#modal-title").textContent = `Raw hit #${h.idx}`;
  $("#modal-body").innerHTML = "";
  $("#modal-body").appendChild(
    el("pre", { class: "mono-block" }, JSON.stringify(h, null, 2))
  );
  $("#modal-root").hidden = false;
}

// ── Enrichment ──────────────────────────────────────────────
async function enrichIps(ips, { focus = false } = {}) {
  if (!ips || !ips.length) return;
  toast(`Looking up ${ips.length} IP${ips.length === 1 ? "" : "s"} on AbuseIPDB…`, { type: "info", timeout: 1800 });
  try {
    const data = await api("/api/enrich", { method: "POST", body: { ips } });
    for (const [ip, d] of Object.entries(data.results || {})) state.enrichment[ip] = { data: d };
    for (const [ip, err] of Object.entries(data.errors || {})) state.enrichment[ip] = { error: err };
    renderEnrichment();
    const n = Object.keys(state.enrichment).length;
    $("#badge-ips").hidden = n === 0;
    $("#badge-ips").textContent = n;
    toast(`Enriched ${Object.keys(data.results || {}).length} IP(s)`, { type: "success" });
    if (focus) switchTab("enrichment");
  } catch (e) {
    toast(e.message, { type: "error", title: "AbuseIPDB failed" });
  }
}

function renderEnrichment() {
  const root = $("#enrichment-list");
  const entries = Object.entries(state.enrichment);
  $("#ips-count-chip").textContent = `${entries.length} IP${entries.length === 1 ? "" : "s"}`;
  root.innerHTML = "";
  if (!entries.length) {
    root.appendChild(el("div", { class: "empty" },
      el("div", { class: "empty-icon" }, "🌐"),
      el("div", { class: "empty-title" }, "No IPs enriched"),
      el("div", { class: "muted" }, "Run a query, then enrich public IPs."),
    ));
    return;
  }
  // Sort by score descending
  entries.sort((a, b) => (b[1].data?.abuseConfidenceScore || 0) - (a[1].data?.abuseConfidenceScore || 0));
  for (const [ip, result] of entries) root.appendChild(ipCard(ip, result));
}

function riskTier(score) {
  if (score >= 75) return "crit";
  if (score >= 40) return "high";
  if (score >= 10) return "mid";
  return "low";
}
function riskLabel(score) {
  if (score >= 75) return "Critical";
  if (score >= 40) return "High";
  if (score >= 10) return "Moderate";
  return "Low";
}

function ipCard(ip, result) {
  if (result.error) {
    return el("div", { class: "ip-card" },
      el("h4", {}, ip),
      el("div", { class: "muted" }, `Lookup failed: ${result.error}`),
    );
  }
  const d = result.data || {};
  const score = d.abuseConfidenceScore || 0;
  const tier = riskTier(score);

  const meta = el("div", { class: "ip-meta" });
  const rows = [
    ["Abuse score",   `${score}% — ${riskLabel(score)}`],
    ["Whitelisted",   d.isWhitelisted ? "Yes" : "No"],
    ["Country",       d.countryName || d.countryCode],
    ["ISP",           d.isp],
    ["Domain",        d.domain],
    ["Usage",         d.usageType],
    ["Total reports", d.totalReports],
    ["Last reported", d.lastReportedAt],
  ].filter(([, v]) => v !== null && v !== undefined && v !== "");
  for (const [k, v] of rows) {
    meta.appendChild(el("div", { class: "k" }, k));
    meta.appendChild(el("div", { class: "v" }, String(v)));
  }

  return el("div", { class: "ip-card" },
    el("h4", {},
      el("span", {}, ip),
      el("span", { class: `risk-badge ${tier}` }, `${score}% ${riskLabel(score)}`),
    ),
    el("div", { class: "score-bar" },
      el("div", { class: `fill ${tier}`, style: `width: ${Math.max(4, score)}%` })),
    meta,
  );
}

async function enrichAll() {
  const ips = [...new Set(state.hits.filter(h => h.src_is_public && h.src_ip).map(h => h.src_ip))];
  if (!ips.length) { toast("No public source IPs to enrich", { type: "warning" }); return; }
  await enrichIps(ips, { focus: true });
}

// ── AI Analysis ─────────────────────────────────────────────
async function analyzeHit(hit) {
  if (!hit.message) {
    toast("This alert has no 'message' field to analyze", { type: "warning" });
    return;
  }
  // Show a preview/edit modal first so users can redact sensitive data.
  openAnalyzeModal(hit);
}

function openAnalyzeModal(hit) {
  $("#modal-title").textContent = `AI Analyze — Match #${hit.idx}`;
  const body = $("#modal-body");
  body.innerHTML = "";
  body.appendChild(el("p", { class: "muted" },
    "Review / redact the message before sending it to Gemini."));
  const ta = el("textarea", {
    rows: 14,
    style: "width:100%;font-family:var(--ff-mono);font-size:12.5px;",
  });
  ta.value = hit.message;
  body.appendChild(ta);
  const bar = el("div", { class: "actions", style: "margin-top:14px;justify-content:flex-end;" },
    el("button", { class: "btn btn-ghost", onclick: () => closeModal() }, "Cancel"),
    el("button", {
      class: "btn btn-primary",
      onclick: async (e) => {
        e.currentTarget.disabled = true;
        e.currentTarget.textContent = "Analyzing…";
        try {
          const data = await api("/api/analyze", {
            method: "POST",
            body: { message: ta.value },
          });
          state.analyses.unshift({
            hit, analysis: data.analysis,
            description_text: data.description_text,
            at: new Date().toISOString(),
          });
          renderAnalyses();
          closeModal();
          toast("Gemini analysis ready", { type: "success" });
          switchTab("analysis");
        } catch (err) {
          toast(err.message, { type: "error", title: "Gemini failed" });
          e.currentTarget.disabled = false;
          e.currentTarget.textContent = "Analyze";
        }
      },
    }, "Analyze"),
  );
  body.appendChild(bar);
  $("#modal-root").hidden = false;
}

function renderAnalyses() {
  const root = $("#analysis-panel");
  root.innerHTML = "";
  if (!state.analyses.length) {
    root.appendChild(el("div", { class: "empty" },
      el("div", { class: "empty-icon" }, "🤖"),
      el("div", { class: "empty-title" }, "No analysis yet"),
      el("div", { class: "muted" }, "Open an alert and click AI analyze."),
    ));
    return;
  }
  for (const a of state.analyses) root.appendChild(analysisCard(a));
}

function analysisCard(a) {
  const A = a.analysis || {};
  const H = a.hit;

  const card = el("article", { class: "analysis-card" });
  card.appendChild(el("header", {},
    el("h3", {}, `Match #${H.idx} — `,
      el("span", { class: "sig" }, H.signature || "(no signature)")),
    el("div", { class: "muted" },
      [H.timestamp || "", A.event ? ` • ${A.event}` : "", ` • analyzed ${new Date(a.at).toLocaleString()}`].join("")),
  ));

  const sec = (title, body) => el("section", { class: "analysis-section" },
    el("h4", {}, title),
    body,
  );

  if (A.summary) card.appendChild(sec("Summary", el("p", {}, A.summary)));

  const netRows = [
    ["Time & date",       A.time_and_date],
    ["Network protocol",  A.network_protocol],
    ["Flow ID",           A.flow_id],
    ["Client ID",         A.client_id],
    ["Source IP",         A.source_ip],
    ["Source port",       A.source_port],
    ["Source bytes",      A.source_bytes],
    ["Source country",    A.source_geo_country_name],
    ["Destination IP",    A.destination_ip],
    ["Destination port",  A.destination_port],
    ["Destination bytes", A.destination_bytes],
  ].filter(([, v]) => v != null && v !== "");
  if (netRows.length) {
    const grid = el("div", { class: "kv-row" });
    for (const [k, v] of netRows) {
      grid.appendChild(el("div", { class: "k" }, k));
      grid.appendChild(el("div", { class: "v" }, String(v)));
    }
    card.appendChild(sec("Network details", grid));
  }

  const incidentRows = [
    ["Event",        A.event],
    ["Target asset", A.target_asset],
  ].filter(([, v]) => v != null && v !== "");
  if (incidentRows.length) {
    const grid = el("div", { class: "kv-row" });
    for (const [k, v] of incidentRows) {
      grid.appendChild(el("div", { class: "k" }, k));
      grid.appendChild(el("div", { class: "v" }, String(v)));
    }
    card.appendChild(sec("Incident", grid));
  }

  const paras = [
    ["What occurred",   A.what_occurred],
    ["Why it happened", A.why_it_happened],
    ["The result",      A.the_result],
    ["Key details",     A.key_details],
  ].filter(([, v]) => v);
  for (const [t, v] of paras) card.appendChild(sec(t, el("p", {}, v)));

  if (A.security_action) card.appendChild(sec("Recommended action", el("p", {}, A.security_action)));
  if (A.additional_information) card.appendChild(sec("Additional info", el("p", {}, A.additional_information)));

  const actions = el("div", { class: "alert-actions", style: "padding:14px 20px;border-top:1px solid var(--border);" },
    el("button", {
      class: "btn btn-primary btn-sm",
      onclick: () => draftMantisTicket(a),
    }, "🎫 Create Mantis ticket"),
    el("button", {
      class: "btn btn-secondary btn-sm",
      onclick: async () => {
        try { await navigator.clipboard.writeText(a.description_text); toast("Description copied", { type: "success", timeout: 1500 }); }
        catch { toast("Copy failed", { type: "error" }); }
      },
    }, "📋 Copy description"),
  );
  card.appendChild(actions);

  return card;
}

// ── Tickets ─────────────────────────────────────────────────
async function draftMantisTicket(a) {
  // Suggest a project from the hostname.
  let suggested = null;
  try {
    const res = await api("/api/mantis/suggest-project", {
      method: "POST",
      body: { hostname: a.hit.hostname || "" },
    });
    suggested = res.suggested;
  } catch (_) { /* non-fatal */ }

  state.pendingTicket = {
    summary: a.analysis.summary || "Incident Report",
    description: a.description_text,
    steps_to_reproduce: a.hit.discover_url || "",
    additional_information: a.analysis.additional_information || "",
    project_id: suggested ? suggested.id : (state.config.mantis_projects[0]?.id || 1),
    project_name: suggested ? suggested.name : (state.config.mantis_projects[0]?.name || ""),
    view_state: "private",
    _source_analysis: a,
  };
  renderTickets();
  switchTab("tickets");
  toast(suggested ? `Suggested project: ${suggested.name}` : "Ticket drafted", { type: "info" });
}

function renderTickets() {
  const root = $("#tickets-panel");
  root.innerHTML = "";

  if (!state.pendingTicket && !state.tickets.length) {
    root.appendChild(el("div", { class: "empty" },
      el("div", { class: "empty-icon" }, "🎫"),
      el("div", { class: "empty-title" }, "No tickets drafted"),
      el("div", { class: "muted" }, "Run an AI analysis first, then click Create Mantis ticket."),
    ));
    return;
  }

  if (state.pendingTicket) {
    root.appendChild(ticketDraftCard(state.pendingTicket));
  }
  for (const t of state.tickets) root.appendChild(ticketSubmittedCard(t));
}

function ticketDraftCard(t) {
  const projects = state.config?.mantis_projects || [];
  const card = el("article", { class: "analysis-card" });
  card.appendChild(el("header", {},
    el("h3", {}, "Draft Mantis ticket"),
    el("div", { class: "muted" }, "Review & edit before submitting."),
  ));

  const sec = (label, input) => el("section", { class: "analysis-section" },
    el("h4", {}, label),
    input,
  );

  const summary = el("input", { type: "text" });
  summary.value = t.summary;
  summary.addEventListener("input", () => t.summary = summary.value);

  const description = el("textarea", { rows: 14, style: "font-family:var(--ff-mono);font-size:12.5px;" });
  description.value = t.description;
  description.addEventListener("input", () => t.description = description.value);

  const steps = el("input", { type: "text", placeholder: "OpenSearch Discover permalink" });
  steps.value = t.steps_to_reproduce;
  steps.addEventListener("input", () => t.steps_to_reproduce = steps.value);

  const addl = el("textarea", { rows: 3 });
  addl.value = t.additional_information;
  addl.addEventListener("input", () => t.additional_information = addl.value);

  const projectSel = el("select", {});
  for (const p of projects) {
    const opt = el("option", { value: p.id }, `${p.name} (#${p.id})`);
    if (p.id === t.project_id) opt.selected = true;
    projectSel.appendChild(opt);
  }
  projectSel.addEventListener("change", () => {
    t.project_id = parseInt(projectSel.value, 10);
    t.project_name = projects.find(p => p.id === t.project_id)?.name || "";
  });

  const visSel = el("select", {},
    el("option", { value: "private" }, "🔒 Private"),
    el("option", { value: "public" }, "🌐 Public"),
  );
  visSel.value = t.view_state || "private";
  visSel.addEventListener("change", () => t.view_state = visSel.value);

  card.appendChild(sec("Summary", summary));
  card.appendChild(sec("Description", description));
  card.appendChild(sec("Steps to reproduce", steps));
  card.appendChild(sec("Additional information", addl));

  const metaGrid = el("div", { class: "field-row" },
    el("label", { class: "field" }, el("span", { class: "field-label" }, "Project"), projectSel),
    el("label", { class: "field" }, el("span", { class: "field-label" }, "Visibility"), visSel),
  );
  card.appendChild(sec("Metadata", metaGrid));

  const bar = el("div", { class: "alert-actions", style: "padding:14px 20px;border-top:1px solid var(--border);" },
    el("button", {
      class: "btn btn-primary",
      onclick: async (e) => {
        e.currentTarget.disabled = true;
        e.currentTarget.textContent = "Submitting…";
        try {
          const payload = { ...t };
          delete payload._source_analysis;
          const res = await api("/api/mantis/submit", { method: "POST", body: payload });
          state.tickets.unshift({ ticket: t, result: res });
          state.pendingTicket = null;
          renderTickets();
          toast(`Ticket submitted — #${res.issue_id}`, { type: "success" });
        } catch (err) {
          toast(err.message, { type: "error", title: "Mantis failed" });
          e.currentTarget.disabled = false;
          e.currentTarget.textContent = "Submit";
        }
      },
    }, "Submit"),
    el("button", {
      class: "btn btn-ghost",
      onclick: () => { state.pendingTicket = null; renderTickets(); },
    }, "Discard"),
  );
  card.appendChild(bar);

  return card;
}

function ticketSubmittedCard(t) {
  const id = t.result?.issue_id;
  const url = t.result?.ticket_url;
  return el("article", { class: "analysis-card" },
    el("header", {},
      el("h3", {}, `Submitted — Ticket #${id ?? "?"}`),
      el("div", { class: "muted" }, t.ticket.summary),
    ),
    el("section", { class: "analysis-section" },
      url
        ? el("a", { href: url, target: "_blank", rel: "noopener", class: "btn btn-secondary btn-sm" }, "↗ Open in Mantis")
        : el("div", { class: "muted" }, "No URL returned by Mantis API."),
    ),
  );
}

// ── Modal ───────────────────────────────────────────────────
function closeModal() { $("#modal-root").hidden = true; }
function initModal() {
  $("#modal-root").addEventListener("click", (e) => {
    if (e.target.closest("[data-close]")) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("#modal-root").hidden) closeModal();
  });
}

// ── Keyboard shortcuts ──────────────────────────────────────
function initShortcuts() {
  document.addEventListener("keydown", (e) => {
    const tag = (e.target && e.target.tagName) || "";
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(tag);

    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runQuery();
      return;
    }
    if (typing) return;

    if (e.key === "/") {
      e.preventDefault();
      switchTab("alerts");
      $("#alerts-filter").focus();
    } else if (e.key.toLowerCase() === "t") {
      $("#theme-toggle").click();
    } else if (/^[1-6]$/.test(e.key)) {
      const order = ["query", "alerts", "enrichment", "analysis", "tickets", "manual"];
      switchTab(order[parseInt(e.key, 10) - 1]);
    }
  });
}

// ── Init ────────────────────────────────────────────────────
function init() {
  initTheme();
  initModal();
  initShortcuts();
  initQueryForm();

  $$(".nav-item").forEach(b => {
    b.addEventListener("click", () => switchTab(b.dataset.tab));
  });

  $("#alerts-filter").addEventListener("input", (e) => {
    state.filter = e.target.value;
    renderAlerts();
  });
  $("#enrich-all-btn").addEventListener("click", () => enrichAll());

  loadConfig();
}

document.addEventListener("DOMContentLoaded", init);
