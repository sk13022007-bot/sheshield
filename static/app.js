/* SheShield front end. Talks to the existing FastAPI endpoints; no data is invented here. */

// Contract address, ABI and network come from the server (/config), set by the SHESHIELD_CONTRACT_ADDRESS env var.
var SEPOLIA_CHAIN = "0xaa36a7";
var SEL_ANCHOR = "0xeecdf927";     // anchor(bytes32)
var SEL_GET = "0x7feb51d9";        // getAnchor(bytes32)
var MAX_IMAGE_BYTES = 8 * 1024 * 1024;

var $ = function (s, r) { return (r || document).querySelector(s); };
var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

function esc(s) {
  return String(s === null || s === undefined ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}
function ic(name, cls) { var w = /ic-lg/.test(cls || "") ? 22 : /ic-sm/.test(cls || "") ? 15 : 18; return '<svg width="' + w + '" height="' + w + '" class="ic ' + (cls || "") + '" aria-hidden="true"><use href="#i-' + name + '"/></svg>'; }
function shortHash(h) { return h && h.length > 20 ? h.slice(0, 10) + "…" + h.slice(-8) : (h || ""); }
function fmtDate(iso) {
  var d = new Date(iso);
  if (isNaN(d)) return iso || "";
  return d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}
function fmtSize(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB"; }

/* ---------- Severity vocabulary ---------- */
var SEV = {
  none:   { label: "No patterns found", pill: "p-none" },
  low:    { label: "Low concern", pill: "p-low" },
  medium: { label: "Concerning", pill: "p-medium" },
  high:   { label: "High risk", pill: "p-high" }
};
function sevOf(s) { return SEV[s] ? s : "none"; }
function sevPill(s) { s = sevOf(s); return '<span class="pill ' + SEV[s].pill + '">' + SEV[s].label + "</span>"; }
var CATEGORY = {
  sextortion: "Sextortion (intimate-media threat)", blackmail_extortion: "Blackmail or extortion", threat: "Threat of violence",
  harassment_abuse: "Harassment or abusive remarks", cyberstalking_contact: "Cyberstalking or repeated contact",
  impersonation: "Impersonation", romance_scam: "Romance scam pattern", financial_scam: "Financial scam pattern",
  phishing: "Phishing pattern", coercive_manipulation: "Coercive control", benign: "No threat pattern found"
};
var LANG = { en: "English", hi: "Hindi", kn: "Kannada", hinglish: "Hinglish", kanglish: "Kanglish" };

/* ---------- State ---------- */
var state = {
  loaded: false,
  items: [],
  verify: null,        // {ok, items_checked} | {ok:false, tampered_at_id}
  verifiedAt: null,
  anchor: null,        // {tx_hash, vault_hash, created_at}
  latestHash: null,
  chain: { status: "unchecked" },   // result of reading the transaction from the blockchain
  wallet: { account: null, chainId: null },
  image: null,         // {sha, identifiers}
  file: null,
  analysis: null,
  analysisStale: false,
  pendingFile: null,
  reportTs: null,
  config: null,
  auth: { authenticated: false },
  intel: null
};

/* ---------- API ---------- */
async function api(path, method, body) {
  var opts = { method: method || "GET", headers: {}, credentials: "same-origin" };
  if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  var res;
  try { res = await fetch(path, opts); }
  catch (e) { showOffline(true); var oe = new Error("Can't reach the SheShield server. Make sure it is running, then try again."); oe.offline = true; throw oe; }
  if (!state.refreshing) showOffline(false);
  if (!res.ok) {
    var detail = "";
    try { detail = (await res.json()).detail || ""; } catch (e) {}
    var err = new Error(detail || ("The server returned an error (" + res.status + ")."));
    err.status = res.status;
    if (res.status === 401 && path.indexOf("/auth/") !== 0) { state.auth = { authenticated: false }; if (window.showLock) showLock("expired"); }
    throw err;
  }
  return res.json();
}
function showOffline(on) {
  var el = $("#offline");
  if (on) {
    el.innerHTML = ic("alert", "ic-sm") + "<span><b>Server not reachable.</b> Start it with <span class='mono'>uvicorn main:app</span> and refresh this page.</span>";
  }
  el.hidden = !on;
}

/* ---------- Toasts & dialog ---------- */
function toast(msg, type, action) {
  var t = document.createElement("div");
  t.className = "toast t-" + (type || "info");
  var icon = type === "error" ? "alert" : type === "warn" ? "alert" : type === "success" ? "check" : "info";
  t.innerHTML = ic(icon, "ic-sm") + "<span>" + esc(msg) + "</span>";
  if (action) {
    var b = document.createElement("button");
    b.className = "t-act"; b.type = "button"; b.textContent = action.label;
    b.onclick = function () { action.run(); close(); };
    t.appendChild(b);
  }
  $("#toasts").appendChild(t);
  var timer = setTimeout(close, type === "error" ? 8000 : 5000);
  function close() { clearTimeout(timer); t.classList.add("out"); setTimeout(function () { t.remove(); }, 220); }
}

function confirmDialog(o) {
  return new Promise(function (resolve) {
    var dlg = $("#dlg");
    $("#dlgTitle").textContent = o.title;
    $("#dlgBody").innerHTML = o.html;
    var ok = $("#dlgOk"), cancel = $("#dlgCancel");
    ok.textContent = o.confirm || "Confirm";
    ok.className = "btn " + (o.danger ? "btn-danger" : "btn-primary");
    var result = false;
    function done() { ok.onclick = cancel.onclick = null; dlg.onclose = null; resolve(result); }
    ok.onclick = function () { result = true; dlg.close(); };
    cancel.onclick = function () { dlg.close(); };
    dlg.onclose = done;
    dlg.showModal();
    cancel.focus();
  });
}

function setBusy(btn, busy, label) {
  if (busy) { btn.dataset.label = btn.innerHTML; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>' + esc(label); }
  else { btn.disabled = false; if (btn.dataset.label) btn.innerHTML = btn.dataset.label; }
}

function copyText(text) {
  var done = function () { toast("Copied to clipboard", "success"); };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () { toast("Could not copy. Select the text and copy it manually.", "warn"); });
  else toast("Copying is not available in this browser. Select the text and copy it manually.", "warn");
}
document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-copy]");
  if (b) copyText(b.getAttribute("data-copy"));
});

/* ---------- Router ---------- */
var ROUTES = ["overview", "scan", "vault", "proof", "reports", "help", "intel", "legal", "emergency", "contacts", "insights", "settings", "more"];
function route() {
  var r = (location.hash.replace(/^#\/?/, "") || "overview");
  if (ROUTES.indexOf(r) < 0) r = "overview";
  $$("[data-view]").forEach(function (v) { v.hidden = v.dataset.view !== r; });
  $$("[data-route]").forEach(function (a) {
    if (a.dataset.route === r) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  var titles = { overview: "Overview", scan: "Check a message", vault: "Evidence vault", proof: "Blockchain proof", reports: "Reports", help: "Get help", intel: "Incident intelligence", legal: "Legal action & reporting", emergency: "Emergency support", contacts: "Trusted contact", insights: "Safety insights", settings: "Settings & privacy", more: "All sections" };
  document.title = titles[r] + " – SheShield";
  window.scrollTo(0, 0);
  if (r === "scan" && state.pendingFile) { var f = state.pendingFile; state.pendingFile = null; setFile(f); }
  if (r === "reports") renderReportState();
  if (r === "scan") renderResult();
  if (state.auth.authenticated) {
    if (r === "vault" || r === "proof" || r === "overview" || r === "reports" || r === "intel" || r === "legal") refreshData();
    if (window.VIEW_HOOKS && VIEW_HOOKS[r]) VIEW_HOOKS[r]();
  }
}
window.addEventListener("hashchange", route);

/* ---------- Data loading ---------- */
async function refreshData() {
  state.refreshing = true;
  try {
    var settled = await Promise.allSettled([api("/vault"), api("/vault/verify"), api("/anchor"), api("/vault/latest-hash")]);
    var bad = settled.filter(function (x) { return x.status === "rejected"; })[0];
    if (bad) throw bad.reason;
    var res = settled.map(function (x) { return x.value; });
    showOffline(false);
    state.items = Array.isArray(res[0]) ? res[0] : [];
    state.verify = res[1];
    state.verifiedAt = new Date();
    state.anchor = res[2].anchor;
    state.latestHash = res[3].hash;
    state.loaded = true;
  } catch (e) {
    state.loadError = e.message;
    state.loaded = true;
    if (e.offline) showOffline(true);
  }
  state.refreshing = false;
  renderAll();
}
function renderAll() {
  renderOverview(); renderVault(); renderProof(); renderReportState();
}

/* ---------- Helpers over vault data ---------- */
function parseContent(raw) {
  var lines = String(raw || "").split("\n"), sha = null, ids = null, keep = [];
  lines.forEach(function (l) {
    var m;
    if ((m = l.match(/^\[screenshot sha256: ([0-9a-fA-F]{64})\]$/))) sha = m[1];
    else if ((m = l.match(/^\[identifiers: (.*)\]$/))) ids = m[1];
    else keep.push(l);
  });
  return { text: keep.join("\n").trim(), sha: sha, ids: ids };
}
function anchorIndex() {
  if (!state.anchor) return -1;
  for (var i = 0; i < state.items.length; i++) if (state.items[i].hash === state.anchor.vault_hash) return i;
  return -1;
}
function integrityView() {
  var v = state.verify;
  if (!state.items.length) return { tone: "neutral", label: "Nothing to check", sub: "No evidence saved yet" };
  if (!v) return { tone: "neutral", label: "Not checked", sub: "" };
  if (v.ok) return { tone: "none", label: "Intact", sub: v.items_checked + " record" + (v.items_checked === 1 ? "" : "s") + " checked " + timeAgo(state.verifiedAt) };
  return { tone: "high", label: "Tampering detected", sub: "Record #" + v.tampered_at_id + " does not match what was saved" };
}
function timeAgo(d) {
  if (!d) return "";
  var s = Math.round((Date.now() - d.getTime()) / 1000);
  return s < 10 ? "just now" : s < 60 ? s + " seconds ago" : Math.round(s / 60) + " min ago";
}

/* ======================= OVERVIEW ======================= */
function renderOverview() {
  var stats = $("#ovStats"), recent = $("#ovRecent");
  if (!stats) return;
  if (!state.loaded) {
    stats.innerHTML = '<div class="skel skel-line"></div><div class="skel skel-line" style="width:70%"></div><div class="skel skel-line"></div>';
    recent.innerHTML = '<div class="panel panel-pad"><div class="skel skel-line"></div><div class="skel skel-line" style="width:60%"></div></div>';
    return;
  }
  if (state.loadError && !state.items.length) {
    stats.innerHTML = '<div class="note err">' + ic("alert", "ic-sm") + "<span>" + esc(state.loadError) + "</span></div>";
    recent.innerHTML = "";
    return;
  }
  var items = state.items, n = items.length, iv = integrityView();
  var counts = { none: 0, low: 0, medium: 0, high: 0 };
  items.forEach(function (i) { counts[sevOf(i.severity)]++; });
  var html = "";
  if (!n) {
    html = '<p class="muted">Nothing saved yet. When you save a message to the vault it will show up here.</p>';
  } else {
    html += '<div class="sevbar" role="img" aria-label="Evidence by severity">';
    ["high", "medium", "low", "none"].forEach(function (k) { if (counts[k]) html += '<i class="s-' + k + '" style="width:' + (counts[k] / n * 100) + '%"></i>'; });
    html += "</div><div class='sev-legend'>";
    ["high", "medium", "low", "none"].forEach(function (k) { if (counts[k]) html += '<span class="l-' + k + '">' + counts[k] + " " + SEV[k].label.toLowerCase() + "</span>"; });
    html += "</div>";
  }
  var anchorTxt;
  if (!state.anchor) anchorTxt = '<span class="pill p-neutral">Not anchored</span>';
  else if (state.chain.status === "verified") anchorTxt = '<span class="pill p-none">Verified on-chain</span>'; else if (state.chain.status === "confirmed") anchorTxt = '<span class="pill p-info">Confirmed, not yet verified</span>';
  else anchorTxt = '<span class="pill p-info">Submitted, unchecked</span>';
  html += '<dl class="kv" style="margin:0">' +
    '<div><dt>Evidence saved</dt><dd>' + n + "</dd></div>" +
    '<div><dt>Vault integrity</dt><dd><span class="pill p-' + (iv.tone === "neutral" ? "neutral" : iv.tone) + '">' + iv.label + "</span></dd></div>" +
    '<div><dt>Blockchain anchor</dt><dd>' + anchorTxt + "</dd></div></dl>";
  stats.innerHTML = html;

  if (!n) {
    recent.innerHTML = '<div class="panel empty"><div class="ic-wrap">' + ic("vault", "ic-lg") + "</div><h3>Your vault is empty</h3>" +
      "<p>Check a message, then save it. Saved evidence is chained together so any later change can be detected.</p>" +
      '<a class="btn btn-primary" href="#/scan">Check a message</a></div>';
    return;
  }
  recent.innerHTML = '<ol class="chain">' + items.slice().reverse().slice(0, 3).map(function (it, idx, arr) {
    return entryHTML(it, { compact: true, last: idx === arr.length - 1 });
  }).join("") + "</ol>";
}

/* ======================= SCAN ======================= */
function setMode(mode) {
  var img = mode === "img";
  $("#tabImg").setAttribute("aria-selected", img); $("#tabTxt").setAttribute("aria-selected", !img);
  $("#paneImg").hidden = !img;
  var hasText = $("#msg").value.trim().length > 0;
  $("#textWrap").hidden = img ? !hasText : false;
  $("#msgHint").textContent = img ? "Fix any reading mistakes before analyzing" : "English, Hindi or Kannada";
  if (!img) $("#msg").focus();
}
$("#tabImg").onclick = function () { setMode("img"); };
$("#tabTxt").onclick = function () { setMode("txt"); };

function setFile(f) {
  if (!f) return;
  state.fromVoice = false;
  if (!/^image\//.test(f.type)) { toast("That file is not an image. Choose a PNG or JPG screenshot.", "error"); return; }
  if (f.size > MAX_IMAGE_BYTES) { toast("That image is " + fmtSize(f.size) + ". The limit is 8 MB. Try a smaller screenshot.", "error"); return; }
  state.file = f; state.image = null;
  if ($("#previewImg").dataset.url) URL.revokeObjectURL($("#previewImg").dataset.url);
  var url = URL.createObjectURL(f);
  $("#previewImg").src = url; $("#previewImg").dataset.url = url;
  $("#previewName").textContent = f.name || "Pasted image";
  $("#previewSize").textContent = fmtSize(f.size);
  $("#previewBox").hidden = false; $("#dropzone").hidden = true;
  setMode("img");
}
function clearImage() {
  state.file = null; state.image = null;
  $("#file").value = "";
  $("#previewBox").hidden = true; $("#dropzone").hidden = false;
  $("#ocrNote").hidden = true;
  if (state.analysis && state.analysis.fromImage) { state.analysis = null; }
  renderResult();
}

function wireDrop(el, onFile) {
  ["dragenter", "dragover"].forEach(function (ev) { el.addEventListener(ev, function (e) { e.preventDefault(); el.classList.add("is-over"); }); });
  ["dragleave", "drop"].forEach(function (ev) { el.addEventListener(ev, function (e) { e.preventDefault(); el.classList.remove("is-over"); }); });
  el.addEventListener("drop", function (e) { var f = e.dataTransfer && e.dataTransfer.files[0]; if (f) onFile(f); });
}
wireDrop($("#dropzone"), setFile);
$("#dropzone").onclick = function () { $("#file").click(); };
$("#dropzone").onkeydown = function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#file").click(); } };
$("#file").onchange = function () { setFile(this.files[0]); };
$("#btnClear").onclick = clearImage;

wireDrop($("#overviewDrop"), function (f) { state.pendingFile = f; location.hash = "#/scan"; });
$("#overviewFile").onchange = function () { if (this.files[0]) { state.pendingFile = this.files[0]; this.value = ""; location.hash = "#/scan"; } };
$("#overviewDrop").onkeydown = function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#overviewFile").click(); } };

document.addEventListener("paste", function (e) {
  if (location.hash !== "#/scan" || !e.clipboardData) return;
  var files = e.clipboardData.files;
  if (files && files[0] && /^image\//.test(files[0].type)) { e.preventDefault(); setFile(files[0]); }
});

$("#msg").addEventListener("input", function () {
  if (state.analysis) { state.analysisStale = true; $("#btnSave").disabled = true; renderResult(); }
});

$("#btnRead").onclick = async function () {
  if (!state.file) return;
  var btn = this;
  setBusy(btn, true, "Reading…");
  state.analysis = null; renderResult(true);
  try {
    var fd = new FormData(); fd.append("file", state.file);
    var res;
    try { res = await fetch("/analyze-image", { method: "POST", body: fd, credentials: "same-origin" }); }
    catch (e) { showOffline(true); throw new Error("Can't reach the SheShield server. Make sure it is running, then try again."); }
    if (res.status === 401) { state.auth = { authenticated: false }; showLock("expired"); throw new Error("Your vault locked. Unlock it and try again."); }
    if (!res.ok) {
      var detail = ""; try { detail = (await res.json()).detail || ""; } catch (e) {}
      throw new Error(detail || "The server returned an error (" + res.status + ").");
    }
    var r = await res.json();
    state.image = { sha: r.image_sha256, identifiers: r.identifiers || {} };
    $("#msg").value = r.text || "";
    $("#textWrap").hidden = false;
    $("#ocrNote").hidden = !r.text;
    if (!r.text) {
      state.analysis = { empty: true, sha: r.image_sha256, fromImage: true };
      toast("No text could be read from this image.", "warn");
    } else {
      state.analysis = Object.assign({ fromImage: true }, r.analysis);
      state.analysisStale = false;
      $("#btnSave").disabled = false;
      toast("Screenshot read. Check the text, then review the result.", "success");
    }
  } catch (e) {
    state.analysis = { error: e.message };
    toast(e.message, "error");
  } finally { setBusy(btn, false); renderResult(); revealResult(); }
};

$("#btnAnalyze").onclick = async function () {
  var text = $("#msg").value.trim();
  if (!text) { toast("Add a message first: paste text or upload a screenshot.", "warn"); $("#msg").focus(); return; }
  var btn = this;
  setBusy(btn, true, "Analyzing…");
  renderResult(true);
  try {
    var r = await api("/analyze", "POST", { text: text });
    state.analysis = Object.assign({ fromImage: !!state.image }, r);
    state.analysisStale = false;
    $("#btnSave").disabled = false;
  } catch (e) {
    state.analysis = { error: e.message };
    toast(e.message, "error");
  } finally { setBusy(btn, false); renderResult(); revealResult(); }
};

$("#btnSave").onclick = async function () {
  var text = $("#msg").value.trim();
  if (!text) return;
  var withImg = !!state.image;
  var ok = await confirmDialog({
    title: "Save to evidence vault?",
    html: "<p>This adds a permanent record to your vault. Once saved it cannot be edited, because any change would break the chain and show up as tampering.</p>" +
      "<ul><li>Message text and its severity score</li><li>The current time</li>" +
      (withImg ? "<li>The screenshot's fingerprint and details found in it</li>" : "") +
      "</ul><p class='small muted'>The screenshot image is not stored. Keep the original on your device.</p>",
    confirm: "Save to vault"
  });
  if (!ok) return;
  var btn = this; setBusy(btn, true, "Saving…");
  try {
    var r = withImg
      ? await api("/vault/image", "POST", { text: text, image_sha256: state.image.sha, identifiers: state.image.identifiers })
      : await api(state.fromVoice ? "/vault/transcript" : "/vault", "POST", { text: text });
    toast("Saved to vault as record #" + r.id + ".", "success", { label: "View", run: function () { location.hash = "#/vault"; } });
    await refreshData();
  } catch (e) { toast("Could not save: " + e.message, "error"); }
  finally { setBusy(btn, false); $("#btnSave").disabled = !state.analysis || state.analysisStale; }
};

function revealResult() { if (window.innerWidth < 1100) { var r = $('#resultPanel'); if (r) r.scrollIntoView({ behavior: 'smooth', block: 'start' }); } }

function renderResult(loading) {
  var p = $("#resultPanel"), a = state.analysis;
  if (loading) {
    p.innerHTML = '<h2 style="margin-bottom:14px">Analyzing…</h2><div class="skel skel-line" style="height:46px"></div><div class="skel skel-line" style="width:80%"></div><div class="skel skel-line" style="width:60%"></div><div class="skel skel-line"></div>';
    return;
  }
  if (!a) {
    p.innerHTML = '<div class="result-empty"><div class="ic-wrap">' + ic("scan", "ic-lg") + "</div><h3>Your result will appear here</h3>" +
      "<p>Add a screenshot or paste a message, then choose analyze. Nothing is saved until you decide to save it.</p></div>";
    return;
  }
  if (a.error) {
    p.innerHTML = '<div class="note err">' + ic("alert", "ic-sm") + "<span><b>This did not work.</b> " + esc(a.error) + "</span></div>";
    return;
  }
  if (a.empty) {
    p.innerHTML = '<div class="empty"><div class="ic-wrap">' + ic("image", "ic-lg") + "</div><h3>No text found in this image</h3>" +
      "<p>Try a clearer, larger screenshot, or switch to Type or paste and enter the message yourself.</p>" +
      '<p class="small">Image fingerprint (SHA-256)<br><span class="mono">' + esc(a.sha) + "</span></p>" +
      '<button class="btn btn-secondary" id="goTxt" type="button">Type the message instead</button></div>';
    $("#goTxt").onclick = function () { setMode("txt"); };
    return;
  }
  var sev = sevOf(a.severity), score = Number(a.score) || 0, cat = a.category || "benign";
  var lead = a.explanation || "";
  var markIcon = sev === "none" ? "check" : "alert";
  var html = "";
  if (state.analysisStale) html += '<div class="note warn" style="margin-bottom:16px">' + ic("alert", "ic-sm") + "<span>You changed the text. Analyze again to update this result.</span></div>";
  if (a.emergency && a.emergency.sextortion) {
    html += '<div class="note err emergency-note" style="margin-bottom:16px">' + ic("heart", "ic-sm") + '<span><b>You are not alone.</b> This looks like sextortion, which is a crime against you, not something you did wrong. <a href="#/emergency">Open Emergency support</a> for clear steps.</span></div>';
  }
  html += '<div class="verdict v-' + sev + '"><div class="mark">' + ic(markIcon, "ic-lg") + "</div><div><h2>" + SEV[sev].label + "</h2><p>" + esc(CATEGORY[cat] || cat) + "</p></div></div>";
  html += '<p style="margin:14px 0 4px">' + esc(lead) + "</p>";
  html += '<div class="chips" style="margin:10px 0 4px"><span class="pill p-neutral">Confidence: ' + esc(a.confidence || "n/a") + '</span><span class="pill p-neutral">Language: ' + esc(LANG[a.language] || a.language || "unknown") + "</span></div>";
  html += '<div class="meter"><div class="meter-top"><span>Risk score</span><span><b>' + score + "</b> / 100</span></div>" +
    '<div class="meter-track" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + score + '" aria-label="Risk score"><div class="meter-fill f-' + sev + '" style="width:' + score + '%"></div></div>' +
    '<div class="meter-scale"><span>Low below 40</span><span>Concerning 40 to 69</span><span>High 70+</span></div></div>';

  var inds = a.indicators || [];
  html += '<div class="evidence-block"><header><h3>Why this was flagged</h3><span class="tag t-risk">Indicators</span></header>';
  if (inds.length) {
    html += '<ul class="found-list">' + inds.map(function (f) {
      return "<li><b>" + esc(f.label) + "</b><span class='mono small'>" + esc(f.matched) + "</span></li>";
    }).join("") + "</ul>";
  } else html += '<p class="muted">No indicators matched.</p>';
  if ((a.context || []).length) html += '<ul class="ctx-list">' + a.context.map(function (c) { return "<li>" + esc(c) + "</li>"; }).join("") + "</ul>";
  if ((a.secondary_categories || []).length) html += '<p class="small muted">Also partly matched: ' + a.secondary_categories.map(function (c) { return esc(CATEGORY[c] || c); }).join(", ") + ".</p>";
  html += "</div>";

  if (a.ml) {
    html += '<div class="evidence-block"><header><h3>Statistical model</h3><span class="tag t-uncertain">Second opinion</span></header>' +
      '<div class="uncertain-box">Closest category: <b>' + esc(CATEGORY[a.ml.top] || a.ml.top) + "</b> (" + Math.round(a.ml.probability * 100) + '%).<br><span class="muted small">A small model trained on a synthetic, template-based dataset. It supports the rules and can be wrong. See MODEL_CARD.md for measured accuracy.</span></div></div>';
  }

  // identifiers: screenshot (server-extracted) or typed
  if (state.image && a.fromImage) html += identifiersHTML(state.image.identifiers);
  else if ((a.identifiers || []).length) {
    html += '<div class="evidence-block"><header><h3>Identifiers in this text</h3><span class="tag t-detected">Detected</span></header>' +
      a.identifiers.map(function (i) { return '<div class="detected-row"><span class="k">' + esc(i.kind) + '</span><span class="v">' + esc(i.raw) + "</span></div>"; }).join("") + "</div>";
  }

  html += '<div class="evidence-block"><header><h3>What you can do</h3></header><ol class="actions">' +
    (a.next_steps || []).map(function (r) { return "<li>" + esc(r) + "</li>"; }).join("") + "</ol>" +
    '<div class="btn-row" style="margin-top:18px"><a class="btn btn-secondary btn-sm" href="#/legal">Legal action &amp; reporting</a><a class="btn btn-ghost btn-sm" href="#/help">Helplines</a></div></div>';
  p.innerHTML = html;
}

function identifiersHTML(ids) {
  ids = ids || {};
  var rows = "";
  (ids.phones || []).forEach(function (ph) {
    rows += '<div class="detected-row"><span class="k">Phone</span><span class="v">' + esc(ph.display) +
      "<small>" + (ph.valid ? "" : "Format looks invalid. ") + "First issued in: " + esc(ph.region || "unknown") + (ph.carrier ? " · Original carrier: " + esc(ph.carrier) : "") + "</small></span></div>";
  });
  [["Email", ids.emails], ["UPI ID", ids.upi_ids], ["Link", ids.urls], ["Handle", ids.handles]].forEach(function (o) {
    (o[1] || []).forEach(function (v) { rows += '<div class="detected-row"><span class="k">' + o[0] + '</span><span class="v">' + esc(v) + "</span></div>"; });
  });
  var h = '<div class="evidence-block"><header><h3>Details visible in the screenshot</h3><span class="tag t-detected">Detected</span></header>';
  if (!rows) {
    h += '<p class="muted">No phone numbers, emails, links or handles were found. If one is visible in the image, add it to the message text above.</p>';
  } else {
    h += rows + '<div class="note" style="margin-top:12px">' + ic("info", "ic-sm") + "<span>SheShield shows what is visible in the screenshot. It cannot identify who owns a number or account. Region and carrier show only where a number was first issued, and numbers can be spoofed. The police can request real owner details from the telecom operator or platform. You can also report suspected misuse at <b>sancharsaathi.gov.in</b>.</span></div>";
  }
  return h + "</div>";
}

/* ======================= VAULT ======================= */
function itemStatus(it) {
  var v = state.verify;
  if (!v) return { cls: "n-idle", icon: "clock", label: "Not checked", pill: "p-neutral" };
  if (v.ok) return { cls: "n-ok", icon: "check", label: "Unchanged", pill: "p-none" };
  if (it.id < v.tampered_at_id) return { cls: "n-ok", icon: "check", label: "Unchanged", pill: "p-none" };
  if (it.id === v.tampered_at_id) return { cls: "n-bad", icon: "x", label: "Modified after saving", pill: "p-high" };
  return { cls: "n-idle", icon: "clock", label: "Not checked (chain broken above)", pill: "p-neutral" };
}

function entryHTML(it, opts) {
  opts = opts || {};
  var c = parseContent(it.content), st = itemStatus(it);
  var idx = state.items.findIndex(function (x) { return x.id === it.id; });
  var prev = idx > 0 ? state.items[idx - 1] : null;
  var ai = anchorIndex();
  var anchored = ai >= 0 && idx <= ai;
  var broken = state.verify && !state.verify.ok && it.id === state.verify.tampered_at_id;
  var h = '<li class="link' + (broken ? " is-broken" : "") + '"><span class="node ' + st.cls + '" title="' + esc(st.label) + '">' + ic(st.icon) + "</span>";
  h += '<article class="panel entry"><div class="entry-top"><span class="id">Record #' + esc(it.id) + "</span>" + sevPill(it.severity) +
    '<time datetime="' + esc(it.created_at) + '" title="' + esc(it.created_at) + '">' + esc(fmtDate(it.created_at)) + "</time></div>";
  h += '<p class="snippet">' + esc(c.text) + "</p>";
  var mt = it.meta || {};
  h += '<div class="chips"><span class="pill ' + st.pill + '">' + esc(st.label) + "</span>";
  if (mt.category && mt.category !== "benign") h += '<span class="pill p-neutral">' + esc(CATEGORY[mt.category] || mt.category) + "</span>";
  if (mt.language) h += '<span class="pill p-neutral">' + esc(LANG[mt.language] || mt.language) + "</span>";
  if (it.readable === false) h += '<span class="pill p-high">Could not be decrypted</span>';
  if (c.sha) h += '<span class="pill p-neutral pill-ic">' + ic("image", "ic-sm") + "&nbsp;Screenshot fingerprint</span>";
  if (anchored) h += state.chain.status === "verified"
    ? '<span class="pill p-none pill-ic">' + ic("chain", "ic-sm") + "&nbsp;Anchored, verified on-chain</span>"
    : '<span class="pill p-info pill-ic">' + ic("chain", "ic-sm") + "&nbsp;Included in anchor, unchecked</span>";
  h += "</div>";
  if (!opts.compact) {
    h += "<details><summary>" + ic("chevron", "ic-sm") + "Details and hashes</summary>";
    h += '<div class="full">' + esc(c.text) + "</div><dl class='facts'>";
    h += "<div><dt>Saved at (UTC)</dt><dd>" + esc(it.created_at) + "</dd></div>";
    h += "<div><dt>Risk score</dt><dd>" + esc(it.score) + " / 100</dd></div>";
    if (c.sha) h += "<div><dt>Screenshot SHA-256</dt><dd class='hash-line'><span class='mono'>" + esc(c.sha) + "</span><button class='copy' data-copy='" + esc(c.sha) + "' aria-label='Copy screenshot fingerprint'>" + ic("copy", "ic-sm") + "</button></dd></div>";
    if (c.ids) h += "<div><dt>Details found</dt><dd class='mono'>" + esc(c.ids) + "</dd></div>";
    if (mt.indicators && mt.indicators.length) h += "<div><dt>Indicators</dt><dd>" + mt.indicators.map(function (x) { return esc(x.label); }).join("; ") + "</dd></div>";
    if (mt.identifiers && mt.identifiers.length) h += "<div><dt>Normalised identifiers</dt><dd class='mono'>" + mt.identifiers.map(function (x) { return esc(x.kind + ": " + x.value); }).join("<br>") + "</dd></div>";
    h += "<div><dt>Record hash</dt><dd class='hash-line'><span class='mono'>" + esc(it.hash) + "</span><button class='copy' data-copy='" + esc(it.hash) + "' aria-label='Copy record hash'>" + ic("copy", "ic-sm") + "</button></dd></div>";
    h += "<div><dt>Linked to</dt><dd class='mono'>" + (prev ? "Record #" + esc(prev.id) + " · " + esc(prev.hash) : "Start of chain (no earlier record)") + "</dd></div>";
    h += "</dl><div class='btn-row' style='margin-top:12px'><a class='btn btn-secondary btn-sm' href='#/legal' data-ev='" + esc(it.id) + "'>Legal options</a><button class='btn btn-secondary btn-sm' type='button' data-alert='" + esc(it.id) + "'>Alert trusted contact</button></div></details>";
  }
  return h + "</article></li>";
}

function renderVault() {
  var top = $("#vaultTop"), list = $("#vaultList");
  if (!top) return;
  if (!state.loaded) {
    top.innerHTML = '<div><div class="skel skel-line"></div></div><div><div class="skel skel-line"></div></div><div><div class="skel skel-line"></div></div>';
    list.innerHTML = '<div class="panel panel-pad"><div class="skel skel-line"></div><div class="skel skel-line" style="width:70%"></div></div>';
    return;
  }
  var iv = integrityView(), n = state.items.length;
  var anchorLbl, anchorSub;
  if (!state.anchor) { anchorLbl = "Not anchored"; anchorSub = "Publish a fingerprint on the Blockchain proof page"; }
  else if (anchorIndex() < 0) { anchorLbl = "Anchor not in vault"; anchorSub = "Stored anchor does not match any saved record"; }
  else {
    var behind = n - 1 - anchorIndex();
    anchorLbl = behind === 0 ? "Covers all evidence" : behind + " newer item" + (behind === 1 ? "" : "s") + " not covered";
    anchorSub = state.chain.status === "verified" ? "Verified on Sepolia" : "Transaction recorded, not yet checked on-chain";
  }
  top.innerHTML =
    '<div><div class="lbl">Records saved</div><div class="big">' + n + '</div><div class="sub">' + (n ? "Latest: " + esc(fmtDate(state.items[n - 1].created_at)) : "Nothing saved yet") + "</div></div>" +
    '<div><div class="lbl">Integrity check</div><div class="big" style="color:' + (iv.tone === "high" ? "var(--high)" : iv.tone === "none" ? "var(--none)" : "inherit") + '">' + iv.label + '</div><div class="sub">' + esc(iv.sub) + "</div></div>" +
    '<div><div class="lbl">Blockchain anchor</div><div class="big" style="font-size:1.25rem;padding-top:6px">' + anchorLbl + '</div><div class="sub">' + anchorSub + "</div></div>";

  var banner = $("#tamperBanner");
  if (banner) banner.remove();
  if (state.verify && !state.verify.ok) {
    top.insertAdjacentHTML("beforebegin", '<div id="tamperBanner" class="note err" style="margin-bottom:18px">' + ic("alert", "ic-sm") +
      "<span><b>Tampering detected.</b> Record #" + esc(state.verify.tampered_at_id) + " no longer matches the hash it was saved with. Do not rely on this vault as proof until you understand why. Keep your original screenshots.</span></div>");
  }

  if (state.loadError && !n) { list.innerHTML = '<div class="note err">' + ic("alert", "ic-sm") + "<span>" + esc(state.loadError) + "</span></div>"; return; }
  if (!n) {
    list.innerHTML = '<div class="panel empty"><div class="ic-wrap">' + ic("vault", "ic-lg") + "</div><h3>No evidence saved yet</h3>" +
      "<p>Check a message and choose Save to vault. Each saved item is timestamped and chained to the one before it.</p>" +
      '<a class="btn btn-primary" href="#/scan">Check a message</a></div>';
    return;
  }
  var f = $("#sevFilter").value;
  var shown = state.items.slice().reverse().filter(function (i) { return f === "all" || sevOf(i.severity) === f; });
  if (!shown.length) { list.innerHTML = '<div class="panel empty"><h3>No records match this filter</h3><p>Choose All severities to see everything.</p></div>'; return; }
  list.innerHTML = '<ol class="chain">' + shown.map(function (it) { return entryHTML(it); }).join("") + "</ol>" +
    (f === "all" ? '<p class="muted small" style="margin:18px 0 0 52px">Start of chain. Newest records are at the top, and each one is linked to the record below it.</p>' : "");
}
$("#sevFilter").onchange = renderVault;
$("#btnVerify").onclick = async function () {
  var btn = this; setBusy(btn, true, "Verifying…");
  try {
    state.verify = await api("/vault/verify"); state.verifiedAt = new Date();
    renderAll();
    if (!state.items.length) toast("Nothing to verify yet. Save some evidence first.", "warn");
    else if (state.verify.ok) toast("Vault intact. " + state.verify.items_checked + " records checked.", "success");
    else toast("Tampering detected at record #" + state.verify.tampered_at_id + ".", "error");
  } catch (e) { toast("Could not verify: " + e.message, "error"); }
  finally { setBusy(btn, false); }
};

/* ======================= BLOCKCHAIN ======================= */
/* Four distinct states, each backed by something different:
   1 stored locally   : the hash exists in your vault
   2 submitted        : your wallet returned a transaction hash (nothing read back yet)
   3 confirmed        : the receipt was read from the network: mined, succeeded, sent to the SheShield contract
   4 verified         : getAnchor(hash) was read from the contract and the hash matches your current vault records */
function contractAddr() { return state.config && state.config.contract_address; }
function contractOK() { return /^0x[0-9a-fA-F]{40}$/.test(contractAddr() || ""); }
function etherscanTx(h) { return "https://sepolia.etherscan.io/tx/" + h; }
function shortAddr(a) { return a ? a.slice(0, 6) + "…" + a.slice(-4) : ""; }
function encodeAnchor(hash) { return SEL_ANCHOR + hash.toLowerCase(); }
function encodeGet(hash) { return SEL_GET + hash.toLowerCase(); }
function decodeGet(hex) {
  var d = String(hex || "").replace(/^0x/, "");
  if (d.length < 256) return null;
  return { exists: parseInt(d.slice(0, 64), 16) !== 0, anchorer: "0x" + d.slice(88, 128), timestamp: parseInt(d.slice(128 + 32, 192), 16), block: parseInt(d.slice(192 + 32, 256), 16) };
}
function chainStage() {
  // returns 1..4 for the stepper
  if (!state.latestHash) return 0;
  if (!state.anchor) return 1;
  var c = state.chain.status;
  if (c === "verified") return 4;
  if (c === "confirmed") return 3;
  return 2;
}

function renderProof() {
  var st = $("#proofStatus"), steps = $("#proofSteps"), box = $("#proofAnchor");
  if (!st) return;
  if (!state.loaded) { st.innerHTML = '<div class="panel-pad"><div class="skel skel-line"></div><div class="skel skel-line" style="width:60%"></div></div>'; return; }
  var a = state.anchor, c = state.chain, ai = anchorIndex(), n = state.items.length;
  var s;
  var T = {
    none: { cls: "", icon: "chain", title: "Stored locally only", text: n ? "Your evidence fingerprint exists only in this vault. Anchoring is optional: it adds an independent, public timestamp on a test blockchain." : "Save some evidence first. Then you can anchor its fingerprint." },
    submitted: { cls: "s-info", icon: "info", title: "Transaction submitted", text: "Your wallet returned a transaction reference. SheShield has not yet read it back from the blockchain. Choose Check on blockchain." },
    pending: { cls: "s-info", icon: "clock", title: "Waiting for confirmation", text: "The network has seen this transaction but it is not in a block yet. Check again in a minute." },
    confirmed: { cls: "s-info", icon: "check", title: "Transaction confirmed", text: "The receipt shows the transaction was mined and succeeded on Sepolia, sent to the SheShield contract. The stored fingerprint has not yet been read back from the contract." },
    verified: { cls: "s-ok", icon: "check", title: "Hash verified on the blockchain", text: "The fingerprint was read from the SheShield contract on Sepolia and it matches a record in your vault, whose integrity check still passes." },
    mismatch: { cls: "s-bad", icon: "alert", title: "Does not match", text: "Either the contract has no such fingerprint, or your vault no longer produces it (a record changed after anchoring). Do not treat this as proof." },
    failed: { cls: "s-bad", icon: "x", title: "Transaction failed", text: "The transaction was mined but reverted, so nothing was recorded. Anchor again." },
    notfound: { cls: "s-warn", icon: "alert", title: "Transaction not found", text: "Your wallet's network has no record of this transaction. It may still be propagating, or your wallet is on a different network." },
    wrongnet: { cls: "s-warn", icon: "alert", title: "Wallet is on another network", text: "Switch your wallet to the Sepolia test network, then check again." },
    nowallet: { cls: "s-warn", icon: "wallet", title: "Wallet needed to check", text: "A browser wallet such as MetaMask is needed to read the blockchain from here. You can also open the transaction on Etherscan, or use scripts/verify_anchor.py." },
    checking: { cls: "s-info", icon: "clock", title: "Checking the blockchain…", text: "Reading the receipt and the contract through your wallet." },
    nocontract: { cls: "s-warn", icon: "alert", title: "Contract address not configured", text: "The server has no deployed contract address. See README, section Blockchain, to deploy it and set SHESHIELD_CONTRACT_ADDRESS." }
  };
  if (!a) s = T.none;
  else if (!contractOK()) s = T.nocontract;
  else s = T[c.status] || T.submitted;
  var coverage = "";
  if (a) {
    if (ai < 0) coverage = '<div class="note warn" style="margin-top:12px">' + ic("alert", "ic-sm") + "<span>The anchored hash does not match any record in this vault.</span></div>";
    else if (ai === n - 1) coverage = '<div class="note ok" style="margin-top:12px">' + ic("check", "ic-sm") + "<span>The anchored hash matches your latest vault record. All " + n + " record" + (n === 1 ? "" : "s") + " are covered.</span></div>";
    else coverage = '<div class="note warn" style="margin-top:12px">' + ic("alert", "ic-sm") + "<span>" + (n - 1 - ai) + " record" + (n - 1 - ai === 1 ? " was" : "s were") + " added after the last anchor. Anchor again to cover " + (n - 1 - ai === 1 ? "it" : "them") + ".</span></div>";
  }
  st.innerHTML = '<div class="status-hero ' + s.cls + '"><div class="mark">' + ic(s.icon, "ic-lg") + "</div><div><h2>" + s.title + "</h2><p>" + s.text + "</p>" +
    (a ? "<div class='btn-row' style='margin-top:14px'><button class='btn btn-primary btn-sm' id='btnCheckChain' type='button'" + (c.status === "checking" ? " disabled" : "") + ">Check on blockchain</button>" +
      "<a class='btn btn-secondary btn-sm' target='_blank' rel='noopener' href='" + esc(etherscanTx(a.tx_hash)) + "'>View on Etherscan" + ic("external", "ic-sm") + "</a></div>" : "") +
    coverage + "</div></div>";
  if ($("#btnCheckChain")) $("#btnCheckChain").onclick = verifyOnChain;

  var stage = chainStage(), connected = !!state.wallet.account;
  var labels = [["Stored locally", "The fingerprint is in your vault."], ["Submitted", "Wallet returned a transaction hash."], ["Confirmed", "Receipt read: mined and succeeded."], ["Verified", "Hash read back from the contract and matched."]];
  steps.innerHTML = labels.map(function (l, i) {
    return '<div class="' + (stage > i ? "done" : "") + '"><span class="n">' + (i + 1) + "</span><h3>" + l[0] + "</h3><p>" + l[1] + "</p></div>";
  }).join("");

  var h = "<h2 style='margin-bottom:6px'>Anchor your vault</h2>";
  h += "<p class='muted' style='margin-bottom:14px'>Fingerprint of your latest evidence record:</p>";
  if (state.latestHash) h += "<div class='hash-line' style='margin-bottom:16px'><span class='mono'>" + esc(state.latestHash) + "</span><button class='copy' data-copy='" + esc(state.latestHash) + "' aria-label='Copy hash'>" + ic("copy", "ic-sm") + "</button></div>";
  else h += "<div class='note' style='margin-bottom:16px'>" + ic("info", "ic-sm") + "<span>No evidence saved yet. <a href='#/scan'>Check a message</a> and save it first.</span></div>";
  if (!contractOK()) h += "<div class='note err' style='margin-bottom:14px'>" + ic("alert", "ic-sm") + "<span>No contract address is configured on the server, so anchoring is unavailable. Deploy <span class='mono'>contracts/SheShieldAnchor.sol</span> and set <span class='mono'>SHESHIELD_CONTRACT_ADDRESS</span> (see README).</span></div>";
  if (!window.ethereum) h += "<div class='note warn' style='margin-bottom:14px'>" + ic("wallet", "ic-sm") + "<span>No wallet found in this browser. Install MetaMask or open SheShield in a browser that has it.</span></div>";
  h += "<div class='btn-row'>";
  if (window.ethereum && !connected) h += "<button class='btn btn-secondary' id='btnConnect' type='button'>" + ic("wallet", "ic-sm") + "Connect wallet</button>";
  h += "<button class='btn btn-primary' id='btnAnchor' type='button'" + (state.latestHash && contractOK() && window.ethereum ? "" : " disabled") + ">" + ic("chain", "ic-sm") + (a ? "Anchor latest hash again" : "Anchor latest hash") + "</button></div>";
  if (connected) h += "<p class='small muted' style='margin-top:12px'>Wallet " + esc(shortAddr(state.wallet.account)) + " · " + (state.wallet.chainId === SEPOLIA_CHAIN ? "Sepolia test network" : "Not on Sepolia") + "</p>";
  if (contractOK()) h += "<p class='small muted' style='margin-top:8px'>Contract <a class='mono' target='_blank' rel='noopener' href='" + esc(state.config.explorer + "/address/" + contractAddr()) + "'>" + esc(contractAddr()) + "</a> on " + esc(state.config.network) + "</p>";
  if (a) {
    h += "<hr class='rule'><dl class='facts' style='margin-top:0'>" +
      "<div><dt>Anchored hash</dt><dd class='hash-line'><span class='mono'>" + esc(a.vault_hash) + "</span></dd></div>" +
      "<div><dt>Transaction</dt><dd class='hash-line'><a class='mono' target='_blank' rel='noopener' href='" + esc(etherscanTx(a.tx_hash)) + "'>" + esc(a.tx_hash) + "</a></dd></div>" +
      "<div><dt>Submitted</dt><dd>" + esc(fmtDate(a.created_at)) + "</dd></div>" +
      (c.block ? "<div><dt>Block</dt><dd>" + esc(c.block) + "</dd></div>" : "") +
      (c.timestamp ? "<div><dt>On-chain timestamp</dt><dd>" + esc(fmtDate(new Date(c.timestamp * 1000).toISOString())) + "</dd></div>" : "") + "</dl>";
  }
  box.innerHTML = h;
  if ($("#btnConnect")) $("#btnConnect").onclick = connectWallet;
  if ($("#btnAnchor")) $("#btnAnchor").onclick = doAnchor;
}

async function connectWallet() {
  try {
    var accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
    state.wallet.account = accounts[0];
    state.wallet.chainId = await window.ethereum.request({ method: "eth_chainId" });
    toast("Wallet connected.", "success");
  } catch (e) { toast(walletError(e, "Wallet connection was cancelled."), "warn"); }
  renderProof();
}
function walletError(e, fallback) {
  if (e && e.code === 4001) return "You declined the request in your wallet. Nothing was sent.";
  return (e && e.message) || fallback;
}
if (window.ethereum && window.ethereum.on) {
  window.ethereum.on("accountsChanged", function (a) { state.wallet.account = a[0] || null; renderProof(); });
  window.ethereum.on("chainChanged", function (c) { state.wallet.chainId = c; state.chain = { status: "unchecked" }; renderProof(); });
}

async function doAnchor() {
  if (!contractOK()) { toast("No contract address is configured on the server.", "error"); return; }
  if (!window.ethereum) { toast("No wallet found. Install MetaMask or use a browser that has it.", "error"); return; }
  var btn = $("#btnAnchor");
  try {
    var latest = await api("/vault/latest-hash");
    if (!latest.hash) { toast("Save some evidence to the vault first.", "warn"); return; }
    var ok = await confirmDialog({
      title: "Publish this fingerprint?",
      html: "<p>Your wallet will ask you to confirm one transaction on the <b>Sepolia test network</b>.</p>" +
        "<ul><li>Published: only the 64-character hash <span class='mono'>" + esc(shortHash(latest.hash)) + "</span>, your wallet address and the time</li>" +
        "<li>Not published: message text, names, images or phone numbers</li>" +
        "<li>Cost: free test coins, no real money</li></ul>" +
        "<p class='small muted'>Public blockchain entries cannot be deleted, even if you later wipe your vault.</p>",
      confirm: "Open wallet"
    });
    if (!ok) return;
    setBusy(btn, true, "Waiting for wallet…");
    var accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
    state.wallet.account = accounts[0];
    try { await window.ethereum.request({ method: "wallet_switchEthereumChain", params: [{ chainId: SEPOLIA_CHAIN }] }); }
    catch (e) { throw new Error("Please switch your wallet to the Sepolia test network, then try again."); }
    state.wallet.chainId = SEPOLIA_CHAIN;
    var tx = await window.ethereum.request({ method: "eth_sendTransaction", params: [{ from: accounts[0], to: contractAddr(), data: encodeAnchor(latest.hash) }] });
    await api("/anchor", "POST", { tx_hash: tx, vault_hash: latest.hash, mode: "contract", chain_id: SEPOLIA_CHAIN, contract: contractAddr() });
    state.chain = { status: "unchecked" };
    toast("Transaction submitted. It still needs to be confirmed on the network.", "success");
    await refreshData();
  } catch (e) {
    toast(walletError(e, "Anchoring was cancelled."), e && e.code === 4001 ? "warn" : "error");
    setBusy(btn, false);
  }
}

async function verifyOnChain() {
  var a = state.anchor;
  if (!a) return;
  if (!contractOK()) { renderProof(); return; }
  if (!window.ethereum) { state.chain = { status: "nowallet" }; renderProof(); return; }
  state.chain = { status: "checking" }; renderProof();
  var req = function (m, p) { return window.ethereum.request({ method: m, params: p }); };
  try {
    var chainId = await req("eth_chainId");
    state.wallet.chainId = chainId;
    if (chainId !== SEPOLIA_CHAIN) { state.chain = { status: "wrongnet" }; renderAll(); return; }
    var tx = await req("eth_getTransactionByHash", [a.tx_hash]);
    if (!tx) { state.chain = { status: "notfound" }; renderAll(); return; }
    var rc = tx.blockNumber ? await req("eth_getTransactionReceipt", [a.tx_hash]) : null;
    if (!rc) { state.chain = { status: "pending" }; renderAll(); return; }
    if (rc.status !== "0x1") { state.chain = { status: "failed" }; renderAll(); return; }
    var toOk = rc.to && rc.to.toLowerCase() === contractAddr().toLowerCase();
    var block = parseInt(rc.blockNumber, 16);
    if (!toOk) { state.chain = { status: "mismatch", block: block }; await reportState(a.tx_hash, "mismatch"); renderAll(); return; }
    state.chain = { status: "confirmed", block: block };
    await reportState(a.tx_hash, "confirmed");
    // read the anchored fingerprint back from the contract
    var out = decodeGet(await req("eth_call", [{ to: contractAddr(), data: encodeGet(a.vault_hash) }, "latest"]));
    var inVault = state.items.some(function (i) { return i.hash === a.vault_hash; });
    var intact = state.verify && state.verify.ok;
    if (out && out.exists && inVault && intact) {
      state.chain = { status: "verified", block: out.block || block, timestamp: out.timestamp };
      await reportState(a.tx_hash, "verified");
      toast("Verified: the contract holds this fingerprint and it matches your intact vault.", "success");
    } else {
      state.chain = { status: "mismatch", block: block };
      await reportState(a.tx_hash, "mismatch");
    }
    renderAll();
  } catch (e) {
    state.chain = { status: "unchecked" }; renderAll();
    toast("Could not read the blockchain: " + walletError(e, "unknown error"), "error");
  }
}
async function reportState(tx, st) { try { await api("/anchor/state", "POST", { tx_hash: tx, state: st }); } catch (e) {} }

/* ======================= REPORTS ======================= */
function renderReportState() {
  var el = $("#reportState");
  if (!el) return;
  if (!state.loaded) { el.innerHTML = '<div class="skel skel-line"></div>'; return; }
  var n = state.items.length, iv = integrityView(), h = "";
  h += '<dl class="kv" style="margin:0"><div><dt>Evidence items</dt><dd>' + n + "</dd></div>" +
    '<div><dt>Vault integrity</dt><dd><span class="pill p-' + (iv.tone === "neutral" ? "neutral" : iv.tone) + '">' + iv.label + "</span></dd></div>" +
    "<div><dt>Blockchain reference</dt><dd>" + (state.anchor ? "Included" : "None") + "</dd></div></dl>";
  if (!n) h += '<div class="note warn" style="margin-top:14px">' + ic("alert", "ic-sm") + "<span>Your vault is empty, so the report will say that no evidence has been saved. <a href='#/scan'>Check a message</a> first for a useful report.</span></div>";
  if (state.verify && !state.verify.ok) h += '<div class="note err" style="margin-top:14px">' + ic("alert", "ic-sm") + "<span>The report will state that record #" + esc(state.verify.tampered_at_id) + " failed the integrity check.</span></div>";
  el.innerHTML = h;
}
$("#btnPreview").onclick = async function () {
  var btn = this, frame = $("#pdfFrame");
  setBusy(btn, true, "Building report…");
  frame.innerHTML = '<div class="pdf-placeholder"><div><span class="spinner" style="margin-bottom:12px"></span><p class="small">Building your report…</p></div></div>';
  try {
    var res = await fetch("/report", { credentials: "same-origin" });
    if (!res.ok) throw new Error("The server could not build the report (" + res.status + ").");
    var blob = await res.blob();
    if (state.reportUrl) URL.revokeObjectURL(state.reportUrl);
    state.reportUrl = URL.createObjectURL(blob);
    frame.innerHTML = '<iframe title="Report preview" src="' + state.reportUrl + '"></iframe>';
  } catch (e) {
    var msg = e instanceof TypeError ? "Can't reach the SheShield server." : e.message;
    frame.innerHTML = '<div class="pdf-placeholder"><div class="note err" style="text-align:left">' + ic("alert", "ic-sm") + "<span>" + esc(msg) + "</span></div></div>";
    toast("Could not build the report. " + msg, "error");
  } finally { setBusy(btn, false); }
};
$("#btnDownload").onclick = async function () {
  var btn = this;
  setBusy(btn, true, "Preparing…");
  try {
    var res = await fetch("/report", { credentials: "same-origin" });
    if (!res.ok) throw new Error("The server could not build the report (" + res.status + ").");
    var blob = await res.blob();
    var url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = "SheShield_Complaint_Report.pdf";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    toast("Report downloaded.", "success");
  } catch (e) {
    toast("Could not download the report. " + (e instanceof TypeError ? "Can't reach the SheShield server." : e.message), "error");
  } finally { setBusy(btn, false); }
};

/* ---------- Boot ---------- */
window.sheshieldBoot = async function () {
  if (location.protocol === "file:") { $("#fileNotice").hidden = false; }
  setMode("img");
  renderResult();
  try {
    state.config = await api("/config");
    state.auth = await api("/auth/status");
  } catch (e) { state.auth = { authenticated: false }; }
  if (!state.auth.authenticated) { showLock(); return; }
  await enterApp();
};
window.enterApp = async function () {
  $("#lock").hidden = true; document.body.classList.remove("is-locked");
  $("#whoami").textContent = "Vault: " + state.auth.username; $("#btnLock").hidden = false;
  if (!state.config) { try { state.config = await api("/config"); } catch (e) {} }
  if (!location.hash) location.hash = "#/overview";
  state.loaded = false; renderAll();
  route();
  await refreshData();
};
