(() => {
  "use strict";

  const root = document.getElementById("console");
  if (!root) return;
  const token = root.dataset.csrfToken;
  const domainSelect = document.getElementById("domain-select");
  const warning = document.getElementById("connection-warning");
  let inFlight = false;

  const text = (tag, value, className) => {
    const node = document.createElement(tag);
    node.textContent = value == null || value === "" ? "—" : String(value);
    if (className) node.className = className;
    return node;
  };
  const cell = value => {
    const node = document.createElement("td");
    node.textContent = value == null || value === "" ? "—" : String(value);
    return node;
  };
  const table = (headers, rows) => {
    if (!rows.length) return text("p", "No entries in this domain.", "empty-state");
    const wrap = document.createElement("table");
    const head = document.createElement("thead");
    const headRow = document.createElement("tr");
    headers.forEach(label => headRow.append(text("th", label)));
    head.append(headRow);
    const body = document.createElement("tbody");
    rows.forEach(values => {
      const row = document.createElement("tr");
      values.forEach(value => row.append(cell(value)));
      body.append(row);
    });
    wrap.append(head, body);
    return wrap;
  };
  const replace = (id, node) => document.getElementById(id).replaceChildren(node);
  const time = value => value || "—";
  const evidenceText = value => value == null ? "No evidence supplied" : JSON.stringify(value);

  function render(data) {
    const capture = data.capture || {};
    document.getElementById("capture-title").textContent = capture.state || "Unknown";
    document.getElementById("capture-error").textContent = capture.error || "No capture error reported.";
    document.getElementById("last-packet").textContent = capture.last_packet_at_ist || "No packets observed";

    const attempts = (data.events || []).filter(item => item.kind === "connection_attempt");
    const appEvents = (data.events || []).filter(item => item.kind !== "connection_attempt");
    const alerts = data.alerts || [];
    const blocks = data.blocks || [];
    document.getElementById("attempt-count").textContent = String(attempts.length);
    document.getElementById("event-count").textContent = String(appEvents.length);
    document.getElementById("alert-count").textContent = String(alerts.length);
    document.getElementById("block-count").textContent = String(blocks.length);

    replace("attempts-list", table(
      ["Time (IST)", "Source address", "Destination", "Port", "Observed domain"],
      attempts.map(item => [time(item.time_ist), item.src_ip, item.dst_ip, item.dst_port, item.domain])
    ));
    replace("events-list", table(
      ["Time (IST)", "Event", "Source", "Account context", "Signature"],
      appEvents.map(item => [
        time(item.time_ist), item.kind, item.src_ip,
        item.username || "Not provided",
        item.signature_valid === true ? "Valid" : item.signature_valid === false ? "Invalid" : "Not signed"
      ])
    ));
    replace("alerts-list", table(
      ["Time (IST)", "Rule and reason", "Flagged source", "Flagged username (attempted/authenticated context)", "Evidence"],
      alerts.map(item => [
        time(item.time_ist), [item.rule, item.summary].filter(Boolean).join(": "),
        item.src_ip, item.username || "Not provided", evidenceText(item.evidence)
      ])
    ));

    const list = document.createElement("div");
    if (!blocks.length) {
      list.append(text("p", "No blocked addresses.", "empty-state"));
    } else {
      blocks.forEach(block => {
        const row = document.createElement("article");
        row.className = "block-row";
        const description = document.createElement("div");
        description.append(text("strong", block.ip));
        description.append(text("p", (block.reason || "No reason recorded") + " · Added by " + (block.created_by || "Unknown") + " · Added (IST) " + (block.created_at_ist || "")));
        const form = document.createElement("form");
        form.method = "post";
        form.action = "/blocks/" + encodeURIComponent(String(block.ip)) + "/remove";
        const csrf = document.createElement("input");
        csrf.type = "hidden";
        csrf.name = "csrf_token";
        csrf.value = token;
        const button = text("button", "Unblock", "button-secondary");
        button.type = "submit";
        form.append(csrf, button);
        row.append(description, form);
        list.append(row);
      });
    }
    replace("blocks-list", list);

    const options = new Set(["live", ...(data.domains || [])]);
    if (!options.has(domainSelect.value)) options.add(domainSelect.value);
    const selected = domainSelect.value;
    domainSelect.replaceChildren();
    [...options].sort().forEach(value => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value === "live" ? "Live" : value;
      option.selected = value === selected;
      domainSelect.append(option);
    });
    warning.hidden = true;
  }

  async function refresh() {
    if (inFlight) return;
    inFlight = true;
    const requestedDomain = domainSelect.value || "live";
    try {
      const query = new URLSearchParams({domain: requestedDomain});
      const response = await fetch("/api/snapshot?" + query.toString(), {
        headers: {Accept: "application/json"},
        credentials: "same-origin"
      });
      if (!response.ok) throw new Error("snapshot request failed");
      const data = await response.json();
      if (requestedDomain === domainSelect.value) render(data);
    } catch (_) {
      warning.hidden = false;
    } finally {
      inFlight = false;
      if (domainSelect.value !== requestedDomain) refresh();
    }
  }

  domainSelect.addEventListener("change", refresh);
  refresh();
  window.setInterval(refresh, 2000);
})();
