"use strict";
const $ = (id) => document.getElementById(id);
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const message = (text) => { $("message").textContent = text; };
const format = (number, digits = 1) => Number(number || 0).toFixed(digits);
const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
};
async function action(path, body) {
  const response = await fetch(path, {method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body: JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "Invalid inputs. Check the displayed limits and required fields.";
    throw new Error(detail);
  }
  return data;
}
function metric(label, value) {
  const row = node("div"); row.append(node("span", label), node("strong", value)); return row;
}
function render(data) {
  $("connection").textContent = data.running ? "Experiment running" : "Lab online";
  $("clock").textContent = new Date().toLocaleTimeString();
  $("rps").replaceChildren(document.createTextNode(format(data.telemetry.rps)), node("span", " req/s"));
  $("active").textContent = data.active_connections;
  $("completed").textContent = `${data.completed_requests} completed requests`;
  $("latency").replaceChildren(document.createTextNode(format(data.telemetry.latency_p95)), node("span", " ms"));
  $("error-rate").textContent = `${format(data.telemetry.error_rate * 100)}% service error rate`;
  $("incident-count").textContent = data.incidents.filter(x => !["RESOLVED", "FALSE_POSITIVE"].includes(x.status)).length;
  $("baseline").textContent = data.baseline ? `Normal average ${format(data.baseline.average_rps)} req/s` : "Baseline not learned · reference rules active";
  $("target").textContent = data.lab.target;
  $("lab-state").textContent = data.lab.active ? "OWNED LOOPBACK SERVICE" : "SERVICE STOPPED";
  $("run").disabled = data.running;
  $("control-state").textContent = data.mitigations.length ? "ACTIVE" : "READY";
  $("mitigations").replaceChildren(...(data.mitigations.length ? data.mitigations.map(item => node("p", `${item.mode} · expires ${new Date(item.expires_at * 1000).toLocaleTimeString()}`)) : [node("p", "No active mitigations.", "empty")]));
  const timeline = data.timeline;
  const peak = Math.max(1, ...timeline.map(item => item.rps));
  const points = timeline.length > 1 ? timeline.map((item, i) => `${i * 760 / (timeline.length - 1)},${155 - item.rps / peak * 135}`).join(" ") : "0,155 760,155";
  $("chart").setAttribute("points", points);
  $("chart-max").textContent = `Peak ${format(timeline.length ? peak : 0)} req/s`;
  const rows = data.detections.slice(0, 8).map(item => {
    const row = node("tr"); const severity = node("td");
    severity.append(node("span", item.severity, `severity ${item.severity}`));
    row.append(severity, node("td", item.rule), node("td", `${format(item.observed)} / ${format(item.threshold)}`), node("td", item.explanation)); return row;
  });
  if (rows.length) $("detections").replaceChildren(...rows);
  $("incidents").replaceChildren(...data.incidents.filter(item => !["RESOLVED", "FALSE_POSITIVE"].includes(item.status)).slice(0, 5).map(item => {
    const row = node("div"); row.append(node("strong", `Incident ${item.id.slice(0, 8)}`), node("span", `${item.severity} · ${item.status}`));
    for (const [label, status] of [["Acknowledge", "ACKNOWLEDGED"], ["Resolve", "RESOLVED"], ["False positive", "FALSE_POSITIVE"]]) {
      const button = node("button", label, "ghost");
      button.addEventListener("click", () => perform(() => action(`/api/incidents/${item.id}`, {status})));
      row.append(button);
    }
    return row;
  }));
  const evaluation = data.evaluation;
  const percent = value => value === null ? "Unobserved" : `${format(value * 100)}%`;
  $("evaluation").replaceChildren(metric("Scenario detection rate", percent(evaluation.scenario_detection_rate)), metric("Normal scenario alert rate", percent(evaluation.scenario_false_positive_rate)), metric("Analyst false positives", evaluation.analyst_false_positive_incidents), metric("Missed scenario opportunities", evaluation.missed_scenario_opportunities.length));
  $("history").replaceChildren(...(data.simulations.length ? data.simulations.slice(0, 5).map(item => {
    const row = node("div"); row.append(node("span", item.parameters.scenario), node("small", `${item.parameters.duration}s · ${item.status}`)); return row;
  }) : [node("p", "No simulations recorded.", "empty")]));
  if (data.last_error) message(data.last_error);
}
async function refresh() {
  try { const response = await fetch("/api/status", {cache: "no-store"}); if (!response.ok) throw new Error("Status unavailable"); render(await response.json()); }
  catch { $("connection").textContent = "Disconnected"; message("Cannot reach the local dashboard. Check that the service is running."); }
}
async function perform(callback) {
  try { await callback(); message("Action recorded."); await refresh(); }
  catch (error) { message(error.message); }
}
$("simulation-form").addEventListener("submit", event => {
  event.preventDefault();
  const options = {scenario: $("scenario").value, duration: Number($("duration").value), rate: Number($("rate").value), clients: Number($("clients").value), dry_run: $("dry-run").checked, authorized: $("authorization").checked};
  if (!window.confirm(`Authorize ${options.scenario} for ${options.duration}s at up to ${options.rate} req/s with ${options.clients} synthetic clients on the displayed owned loopback target?`)) return;
  perform(() => action("/api/simulations", {options, confirmed: true})); $("authorization").checked = false;
});
$("cancel").addEventListener("click", () => perform(() => action("/api/simulations/cancel", {confirmed: true})));
$("learn").addEventListener("click", () => perform(() => action("/api/baseline/create", {confirmed: true})));
$("mitigation-form").addEventListener("submit", event => {
  event.preventDefault(); perform(() => action("/api/mitigation/enable", {mode: $("mitigation-mode").value, reason: $("mitigation-reason").value, ttl: 30, rate: 5}));
});
$("reset-mitigation").addEventListener("click", () => { if (window.confirm("Disable all active local mitigation actions?")) perform(() => action("/api/mitigation/reset", {confirmed: true})); });
async function poll() { await refresh(); window.setTimeout(poll, 1000); }
poll();
