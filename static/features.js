/* SheShield features: lock screen, incident intelligence, legal pathway, emergency support,
   trusted contact, insights, settings, voice notes. Uses helpers from app.js (api, esc, ic, toast, ...). */
window.VIEW_HOOKS = {};

/* ======================= LOCK SCREEN ======================= */
var lockMode = "login";
function showLock(reason) {
  var el = $("#lock"); el.hidden = false; document.body.classList.add("is-locked");
  $("#btnLock").hidden = true; $("#whoami").textContent = "";
  var a = state.auth || {};
  if (reason === "expired") lockMode = "login";
  else if (!a.has_accounts) lockMode = "register";
  renderLock(reason);
}
function renderLock(reason) {
  var b = $("#lockBody"), a = state.auth || {}, h = "";
  var note = reason === "expired" ? '<div class="note warn" style="margin-bottom:14px">' + ic("lock", "ic-sm") + "<span>Your vault locked after a period of inactivity. Enter your PIN to continue.</span></div>"
    : reason === "idle" ? '<div class="note warn" style="margin-bottom:14px">' + ic("lock", "ic-sm") + "<span>Locked after " + esc(a.session_minutes || 20) + " minutes without activity.</span></div>" : "";
  if (lockMode === "register") {
    h = "<h1>Create your private vault</h1><p class='muted'>Your evidence is encrypted with a key derived from your PIN. Only you can open it.</p>" + note +
      '<form id="fReg" class="stack" autocomplete="off"><div><label class="field" for="rUser">Vault name</label><input class="input" id="rUser" autocomplete="username" required minlength="3" maxlength="32" placeholder="e.g. my-vault">' +
      '<span class="small muted">3 to 32 letters, numbers, dots, dashes. Not your real name.</span></div>' +
      '<div><label class="field" for="rPin">PIN or passphrase</label><input class="input" id="rPin" type="password" autocomplete="new-password" required minlength="6" maxlength="64">' +
      '<span class="small muted">' + esc(a.pin_rules || "At least 6 characters") + "</span></div>" +
      '<div><label class="field" for="rPin2">Repeat PIN</label><input class="input" id="rPin2" type="password" autocomplete="new-password" required></div>' +
      (a.legacy_available ? '<label class="check"><input type="checkbox" id="rLegacy"> <span>Move the evidence saved before accounts existed into this vault (it will be encrypted).</span></label>' : "") +
      '<div id="lockErr" class="note err" hidden></div><button class="btn btn-primary" type="submit">Create vault</button></form>' +
      (a.has_accounts ? '<p class="small" style="margin-top:14px"><button class="linkbtn" id="toLogin" type="button">I already have a vault</button></p>' : "");
  } else if (lockMode === "recover") {
    h = "<h1>Recover with your recovery code</h1><p class='muted'>Use the code you were shown when you created the vault. There is no other way to recover it.</p>" +
      '<form id="fRec" class="stack" autocomplete="off"><div><label class="field" for="cUser">Vault name</label><input class="input" id="cUser" required></div>' +
      '<div><label class="field" for="cCode">Recovery code</label><input class="input mono" id="cCode" required placeholder="XXXX-XXXX-XXXX-XXXX-XXXX"></div>' +
      '<div><label class="field" for="cPin">New PIN</label><input class="input" id="cPin" type="password" autocomplete="new-password" required minlength="6"></div>' +
      '<div id="lockErr" class="note err" hidden></div><button class="btn btn-primary" type="submit">Set new PIN and unlock</button></form>' +
      '<p class="small" style="margin-top:14px"><button class="linkbtn" id="toLogin" type="button">Back to unlock</button></p>';
  } else {
    h = "<h1>Unlock your vault</h1>" + note +
      '<form id="fLogin" class="stack"><div><label class="field" for="lUser">Vault name</label><input class="input" id="lUser" autocomplete="username" required></div>' +
      '<div><label class="field" for="lPin">PIN</label><input class="input" id="lPin" type="password" autocomplete="current-password" required></div>' +
      '<div id="lockErr" class="note err" hidden></div><button class="btn btn-primary" type="submit">Unlock</button></form>' +
      '<p class="small" style="margin-top:14px"><button class="linkbtn" id="toReg" type="button">Create a new vault</button> &nbsp;·&nbsp; <button class="linkbtn" id="toRec" type="button">Forgot PIN</button></p>';
  }
  h += '<p class="small muted" style="margin-top:18px">Locked vaults cannot be opened without the PIN or recovery code. Too many wrong PINs cause a temporary lock.</p>';
  b.innerHTML = h;
  var err = function (m) { var e = $("#lockErr"); e.innerHTML = ic("alert", "ic-sm") + "<span>" + esc(m) + "</span>"; e.hidden = false; };
  var go = function (id, mode) { var x = $(id); if (x) x.onclick = function () { lockMode = mode; renderLock(); }; };
  go("#toLogin", "login"); go("#toReg", "register"); go("#toRec", "recover");
  if ($("#fLogin")) $("#fLogin").onsubmit = async function (e) {
    e.preventDefault();
    var btn = e.target.querySelector("button[type=submit]"); setBusy(btn, true, "Unlocking…");
    try { var r = await api("/auth/login", "POST", { username: $("#lUser").value, pin: $("#lPin").value }); await afterAuth(r.username); }
    catch (x) { err(x.message); } finally { setBusy(btn, false); }
  };
  if ($("#fReg")) $("#fReg").onsubmit = async function (e) {
    e.preventDefault();
    if ($("#rPin").value !== $("#rPin2").value) { err("The two PINs do not match."); return; }
    var btn = e.target.querySelector("button[type=submit]"); setBusy(btn, true, "Creating…");
    try {
      var r = await api("/auth/register", "POST", { username: $("#rUser").value, pin: $("#rPin").value, claim_legacy: !!($("#rLegacy") && $("#rLegacy").checked) });
      showRecoveryCode(r);
    } catch (x) { err(x.message); } finally { setBusy(btn, false); }
  };
  if ($("#fRec")) $("#fRec").onsubmit = async function (e) {
    e.preventDefault();
    var btn = e.target.querySelector("button[type=submit]"); setBusy(btn, true, "Recovering…");
    try { var r = await api("/auth/recover", "POST", { username: $("#cUser").value, recovery_code: $("#cCode").value, new_pin: $("#cPin").value }); await afterAuth(r.username); }
    catch (x) { err(x.message); } finally { setBusy(btn, false); }
  };
}
async function afterAuth(username) {
  state.auth = await api("/auth/status");
  armIdleTimer();
  await enterApp();
}
function showRecoveryCode(r) {
  $("#lockBody").innerHTML = "<h1>Save your recovery code</h1>" +
    '<div class="note warn" style="margin:10px 0 14px">' + ic("alert", "ic-sm") + "<span>" + esc(r.recovery_note) + "</span></div>" +
    '<div class="recovery mono" id="recCode">' + esc(r.recovery_code) + "</div>" +
    '<div class="btn-row" style="margin:10px 0"><button class="btn btn-secondary btn-sm" data-copy="' + esc(r.recovery_code) + '" type="button">' + ic("copy", "ic-sm") + 'Copy</button><button class="btn btn-secondary btn-sm" id="recPrint" type="button">Print</button></div>' +
    '<label class="check"><input type="checkbox" id="recOk"> <span>I have saved this code somewhere safe.</span></label>' +
    '<button class="btn btn-primary" id="recGo" type="button" disabled style="margin-top:14px">Open my vault</button>';
  $("#recOk").onchange = function () { $("#recGo").disabled = !this.checked; };
  $("#recPrint").onclick = function () { window.print(); };
  $("#recGo").onclick = async function () { await afterAuth(r.username); };
}
document.addEventListener("click", async function (e) {
  if (e.target && e.target.id === "btnLock") { try { await api("/auth/logout", "POST", {}); } catch (x) {} state.auth = await api("/auth/status"); state.items = []; showLock(); }
});

/* idle lock: the server expires the session too; this just shows the lock screen promptly */
var idleTimer = null;
function armIdleTimer() {
  var mins = (state.auth && state.auth.session_minutes) || 20;
  var reset = function () {
    clearTimeout(idleTimer);
    if (!state.auth.authenticated) return;
    idleTimer = setTimeout(async function () {
      try { await api("/auth/logout", "POST", {}); } catch (e) {}
      state.auth = { authenticated: false, has_accounts: true, session_minutes: mins }; state.items = [];
      showLock("idle");
    }, mins * 60 * 1000);
  };
  ["click", "keydown", "touchstart"].forEach(function (ev) { document.addEventListener(ev, reset, { passive: true }); });
  reset();
}

/* ======================= MORE (mobile) ======================= */
VIEW_HOOKS.more = function () {
  var G = [["Protect", [["scan", "scan", "Check a message"], ["emergency", "heart", "Emergency support"]]],
    ["Evidence", [["vault", "vault", "Evidence vault"], ["intel", "link", "Incident intelligence"], ["proof", "chain", "Blockchain proof"]]],
    ["Act", [["legal", "scale", "Legal action & reporting"], ["reports", "file", "Reports"], ["contacts", "user", "Trusted contact"]]],
    ["You", [["insights", "chart", "Safety insights"], ["settings", "gear", "Settings & privacy"], ["help", "help", "Get help"]]]];
  $("#moreList").innerHTML = G.map(function (g) {
    return "<div><h3 style='margin:6px 0'>" + g[0] + "</h3><div class='stack'>" + g[1].map(function (i) {
      return "<a class='panel more-row' href='#/" + i[0] + "'>" + ic(i[1]) + "<span>" + esc(i[2]) + "</span>" + ic("chevron", "ic-sm") + "</a>";
    }).join("") + "</div></div>";
  }).join("");
};

/* ======================= INCIDENT INTELLIGENCE ======================= */
var KIND_LABEL = { phone: "Phone number", email: "Email address", upi: "UPI ID", handle: "Account handle", url: "Link" };
VIEW_HOOKS.intel = async function () {
  var el = $("#intelBody");
  el.innerHTML = '<div class="skel skel-line"></div><div class="skel skel-line" style="width:60%"></div>';
  try {
    var d = await api("/intel/links"); state.intel = d;
    if (!d.total_records) { el.innerHTML = '<div class="panel empty"><div class="ic-wrap">' + ic("link", "ic-lg") + "</div><h3>Nothing to compare yet</h3><p>Save at least two pieces of evidence. Repeated phone numbers, emails, UPI IDs or handles will show up here.</p><a class='btn btn-primary' href='#/scan'>Check a message</a></div>"; return; }
    var h = '<p class="muted small">' + d.records_with_identifiers + " of " + d.total_records + " records contain an identifier. " + esc(d.scope) + "</p>";
    if (!d.groups.length) h += '<div class="panel empty"><h3>No repeated identifiers</h3><p>None of the identifiers found so far appear in more than one record. If a number is only visible inside a screenshot, SheShield reads it by OCR, which can miss digits.</p></div>';
    d.groups.forEach(function (g, gi) {
      h += '<article class="panel panel-pad intel-card"><div class="entry-top"><span class="pill p-medium">' + esc(g.headline) + '</span><span class="pill p-neutral">' + esc(g.confidence) + " confidence</span></div>" +
        "<h2 style='margin:10px 0 2px'>" + esc(KIND_LABEL[g.kind] || g.kind) + ': <span class="mono">' + esc(g.value) + "</span></h2><p>" + esc(g.message) + "</p>" +
        (g.pattern ? "<p class='small'><b>Pattern:</b> " + esc(g.pattern) + "</p>" : "") +
        '<p class="small muted">First seen ' + esc(fmtDate(g.first_seen)) + " · last seen " + esc(fmtDate(g.last_seen)) + "</p>" +
        "<details><summary>" + ic("chevron", "ic-sm") + "Inspect the " + g.count + " related records</summary><div class='stack' style='margin-top:10px'>" +
        g.record_ids.map(function (id) {
          var it = state.items.find(function (x) { return x.id === id; }) || {};
          return "<div class='related'><b>Record #" + esc(id) + "</b> " + sevPill(it.severity) + " <span class='muted small'>" + esc(fmtDate(it.created_at)) + "</span><p class='snippet small'>" + esc(parseContent(it.content).text.slice(0, 220)) + "</p></div>";
        }).join("") + "</div></details>" +
        "<details><summary>" + ic("chevron", "ic-sm") + "Why these were linked, and what to be careful about</summary><p class='small'>" + esc(g.why_linked) + "</p><ul class='small'>" +
        g.cautions.map(function (c) { return "<li>" + esc(c) + "</li>"; }).join("") + "</ul></details></article>";
    });
    if (d.clusters.length) {
      h += "<h2 style='margin:26px 0 8px'>Potentially related incidents</h2><p class='muted small'>Records connected through a shared identifier. Connections are not proof that one person is responsible.</p>";
      d.clusters.forEach(function (c) {
        h += '<div class="panel panel-pad" style="margin-bottom:10px"><b>' + c.record_ids.length + " records</b>: " + c.record_ids.map(function (i) { return "#" + i; }).join(", ") +
          '<p class="small muted">Linked by: ' + (c.shared_identifiers || []).map(function (x) { return esc((KIND_LABEL[x.kind] || x.kind) + " " + x.value + " (" + x.count + " records)"); }).join("; ") + "</p><p class='small muted'>" + esc(c.why_linked) + "</p></div>";
      });
    }
    var linkedTl = (d.timeline || []).filter(function (t) { return t.linked; });
    if (linkedTl.length) {
      h += "<h2 style='margin:26px 0 8px'>Timeline of linked records</h2><ol class='tl'>" + linkedTl.map(function (t) {
        var it = state.items.find(function (x) { return x.id === t.id; }) || {}, cat = it.meta && it.meta.category;
        return "<li><time>" + esc(fmtDate(t.created_at)) + "</time> Record #" + esc(t.id) + " " + sevPill(t.severity) + (cat && cat !== "benign" ? " · " + esc(CATEGORY[cat] || cat) : "") + " " + (t.identifiers || []).map(function (x) { return "<span class='pill p-neutral mono'>" + esc(x.kind + ": " + x.value) + "</span>"; }).join(" ") + "</li>";
      }).join("") + "</ol>";
    }
    h += '<div class="note" style="margin-top:20px">' + ic("info", "ic-sm") + "<span>" + esc(d.disclaimer) + "</span></div>";
    el.innerHTML = h;
  } catch (e) { el.innerHTML = '<div class="note err">' + ic("alert", "ic-sm") + "<span>" + esc(e.message) + "</span></div>"; }
};

/* ======================= LEGAL ======================= */
VIEW_HOOKS.legal = async function (evId) {
  var el = $("#legalBody");
  var sel = state.legalEv;
  if (typeof evId === "number") sel = state.legalEv = evId;
  el.innerHTML = '<div class="skel skel-line"></div><div class="skel skel-line" style="width:60%"></div>';
  try {
    var p = await api("/legal/pathway" + (sel ? "?evidence_id=" + sel : ""));
    var h = '<div class="note info" style="margin-bottom:18px">' + ic("info", "ic-sm") + "<span>" + esc(p.disclaimer) + "</span></div>";
    if (state.items.length) {
      h += '<div class="panel panel-pad" style="margin-bottom:18px"><label class="field" for="legalSel">Based on record</label><select class="input" id="legalSel">' +
        state.items.slice().reverse().map(function (i) { return "<option value='" + i.id + "'" + (i.id === p.evidence_id ? " selected" : "") + ">#" + i.id + " · " + esc(fmtDate(i.created_at)) + " · " + SEV[sevOf(i.severity)].label + (i.meta && i.meta.category ? " · " + esc(CATEGORY[i.meta.category] || i.meta.category) : "") + "</option>"; }).join("") + "</select>" +
        '<p class="small muted" style="margin-top:6px">By default this uses your highest-risk record.</p></div>';
    }
    h += '<div class="panel panel-pad"><h2>' + esc(p.headline) + "</h2>";
    if (p.observed_summary) h += "<p class='muted'>" + esc(p.observed_summary) + "</p>";
    h += '<h3 style="margin-top:16px">How to read this page</h3><div class="status-trio">' +
      ["observed", "alleged", "established"].map(function (k) { var x = p.status_explainer[k]; return '<div><b>' + esc(x.label) + "</b><p class='small'>" + esc(x.meaning) + "</p></div>"; }).join("") + "</div>";
    if (p.observed && p.observed.length) h += "<h3 style='margin-top:16px'>Observed in your message</h3><ul>" + p.observed.map(function (o) { return "<li>" + esc(o) + "</li>"; }).join("") + "</ul>";
    h += "</div>";
    h += '<h2 style="margin:26px 0 10px">Where to report</h2><div class="channels">' + p.channels.map(function (c) {
      return '<div class="panel panel-pad channel"><b>' + esc(c.name) + "</b>" +
        (c.tel ? '<a class="big-tel" href="tel:' + esc(c.tel) + '">' + esc(c.contact) + "</a>" : '<span class="mono">' + esc(c.contact) + "</span>") +
        "<p class='small'>" + esc(c.use_for) + "</p>" + (c.url ? '<a class="small" target="_blank" rel="noopener" href="' + esc(c.url) + '">Open website ' + ic("external", "ic-sm") + "</a>" : "") +
        (c.official === false ? '<span class="pill p-neutral">Not a government service</span>' : "") + "</div>";
    }).join("") + "</div>" +
      '<div class="note warn" style="margin-top:12px">' + ic("alert", "ic-sm") + "<span>" + esc(p.note_1930) + "</span></div>";
    h += '<h2 style="margin:26px 0 8px">Laws that may be relevant</h2>';
    if (!p.provisions.length) h += '<div class="panel empty"><p>No specific provisions are suggested because no threat category was found in your records. You can still report anything that frightens you.</p></div>';
    else {
      h += '<p class="muted small">These are <b>potentially applicable</b> provisions of the Bharatiya Nyaya Sanhita, 2023 and the Information Technology Act, 2000. Each shows why it may be relevant and what must be true. Whether anything applies is for the police and courts to decide. Last checked ' + esc(p.checked_on) + "; confirm current text at <a target='_blank' rel='noopener' href='" + esc(p.verify_at) + "'>indiacode.nic.in</a>.</p>";
      p.provisions.forEach(function (x) {
        h += '<article class="panel panel-pad prov"><div class="entry-top"><b>' + esc(x.ref) + '</b><span class="pill p-neutral">Potentially applicable</span></div><h3 style="margin:6px 0">' + esc(x.title) + "</h3>" +
          "<p class='small'>" + esc(x.covers) + "</p><p><b>Why it may be relevant:</b> " + esc(x.why_relevant) + "</p><p class='small'><b>Only applies if:</b> " + esc(x.applies_if) + "</p>" +
          (x.url ? '<a class="small" target="_blank" rel="noopener" href="' + esc(x.url) + '">Read the provision ' + ic("external", "ic-sm") + "</a>" : "") + "</article>";
      });
    }
    h += '<h2 style="margin:26px 0 8px">Your next steps</h2><ol class="actions panel panel-pad">' + p.next_steps.map(function (s) { return "<li>" + esc(s) + "</li>"; }).join("") + "</ol>" +
      '<div class="btn-row" style="margin-top:14px"><a class="btn btn-primary" href="#/reports">Build the PDF report</a><a class="btn btn-secondary" href="#/vault">Open evidence vault</a></div>';
    el.innerHTML = h;
    if ($("#legalSel")) $("#legalSel").onchange = function () { VIEW_HOOKS.legal(parseInt(this.value, 10)); };
  } catch (e) { el.innerHTML = '<div class="note err">' + ic("alert", "ic-sm") + "<span>" + esc(e.message) + "</span></div>"; }
};
document.addEventListener("click", function (e) {
  var a = e.target.closest("a[data-ev]"); if (a) state.legalEv = parseInt(a.getAttribute("data-ev"), 10);
});

/* ======================= EMERGENCY + LOCAL IMAGE FINGERPRINTS ======================= */
var HASH_KEY = "sheshield_local_hashes";
function loadHashes() { try { return JSON.parse(localStorage.getItem(HASH_KEY) || "[]"); } catch (e) { return []; } }
function saveHashes(l) { try { localStorage.setItem(HASH_KEY, JSON.stringify(l)); return true; } catch (e) { toast("This browser would not store the fingerprint (private mode or storage blocked).", "warn"); return false; } }
function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, "0"); }).join(""); }
async function sha256File(file) { return hex(await crypto.subtle.digest("SHA-256", await file.arrayBuffer())); }
/* dHash: shrink to 9x8 greyscale, compare each pixel to its right neighbour -> 64 bits */
async function dHashFile(file) {
  var url = URL.createObjectURL(file);
  try {
    var img = await new Promise(function (res, rej) { var i = new Image(); i.onload = function () { res(i); }; i.onerror = function () { rej(new Error("This file could not be read as an image.")); }; i.src = url; });
    var c = document.createElement("canvas"); c.width = 9; c.height = 8;
    var g = c.getContext("2d", { willReadFrequently: true }); g.drawImage(img, 0, 0, 9, 8);
    var d = g.getImageData(0, 0, 9, 8).data, bits = "";
    for (var y = 0; y < 8; y++) for (var x = 0; x < 8; x++) {
      var a = (y * 9 + x) * 4, b = (y * 9 + x + 1) * 4;
      var la = 0.299 * d[a] + 0.587 * d[a + 1] + 0.114 * d[a + 2], lb = 0.299 * d[b] + 0.587 * d[b + 1] + 0.114 * d[b + 2];
      bits += la > lb ? "1" : "0";
    }
    var out = ""; for (var i = 0; i < 64; i += 4) out += parseInt(bits.slice(i, i + 4), 2).toString(16);
    return out;
  } finally { URL.revokeObjectURL(url); }
}
function hamming(a, b) { var n = 0; for (var i = 0; i < a.length; i++) { var x = parseInt(a[i], 16) ^ parseInt(b[i], 16); while (x) { n += x & 1; x >>= 1; } } return n; }

VIEW_HOOKS.emergency = async function () {
  var el = $("#emergencyBody");
  try { var g = state.guide || (state.guide = await api("/emergency/guide")); renderEmergency(g); }
  catch (e) { el.innerHTML = '<div class="note err">' + ic("alert", "ic-sm") + "<span>" + esc(e.message) + "</span></div>"; }
};
function renderEmergency(g) {
  var el = $("#emergencyBody");
  var sx = state.items.filter(function (i) { return i.meta && i.meta.category === "sextortion" && (i.severity === "high" || i.severity === "medium"); });
  var h = '<div class="panel panel-pad support-hero"><h2>' + esc(g.headline) + "</h2><p>" + esc(g.subline) + "</p>" +
    (sx.length ? '<div class="note err" style="margin-top:12px">' + ic("heart", "ic-sm") + "<span>" + sx.length + " saved record" + (sx.length === 1 ? " matches" : "s match") + " a sextortion pattern. If you are in danger now, call <a href='tel:112'>112</a>.</span></div>" : "") + "</div>";
  h += '<h2 style="margin:24px 0 10px">What to do, in order</h2><ol class="guide steps7">' + g.actions.map(function (a, i) {
    return '<li class="panel panel-pad"><span class="n">' + (i + 1) + "</span><div><h3>" + esc(a.title) + "</h3><p>" + esc(a.body) + "</p></div></li>";
  }).join("") + "</ol>";
  h += '<div class="btn-row"><a class="btn btn-primary" href="#/scan">Save evidence</a><a class="btn btn-secondary" href="#/legal">Where to report</a><a class="btn btn-secondary" href="#/contacts">Alert a trusted contact</a><a class="btn btn-secondary" href="tel:181">Call 181</a></div>';

  h += '<h2 style="margin:30px 0 6px">Image fingerprints <span class="tag t-uncertain">Local prototype</span></h2>' +
    '<div class="panel panel-pad"><p>' + esc(g.stopncii) + "</p><div class='note warn' style='margin:12px 0'>" + ic("alert", "ic-sm") + "<span><b>" + esc(g.prototype_note) + '</b> <a target="_blank" rel="noopener" href="https://stopncii.org/">stopncii.org</a></span></div>' +
    "<h3>Two kinds of fingerprint</h3><dl class='facts'>" + g.hash_types.map(function (t) { return "<div><dt>" + esc(t.name) + "</dt><dd>" + esc(t.what) + "</dd></div>"; }).join("") + "</dl>" +
    '<div class="note ok" style="margin:12px 0">' + ic("lock", "ic-sm") + "<span>The image is read by your browser only. It is never uploaded, and not even saved. Only the two fingerprints below are kept, in this browser's storage.</span></div>" +
    '<div class="btn-row"><label class="btn btn-primary" for="hashFile" tabindex="0">' + ic("image", "ic-sm") + 'Choose image to fingerprint</label><input type="file" id="hashFile" accept="image/*" hidden>' +
    '<label class="btn btn-secondary" for="matchFile" tabindex="0">Check an image against my fingerprints</label><input type="file" id="matchFile" accept="image/*" hidden></div>' +
    '<div id="hashOut" style="margin-top:14px"></div><div id="hashList" style="margin-top:14px"></div></div>';
  el.innerHTML = h;
  renderHashList();
  $("#hashFile").onchange = async function () {
    var f = this.files[0]; this.value = ""; if (!f) return;
    try {
      var r = await Promise.all([sha256File(f), dHashFile(f)]);
      var list = loadHashes(), item = { id: Date.now(), added: new Date().toISOString(), sha256: r[0], dhash: r[1] };
      if (list.some(function (x) { return x.sha256 === item.sha256; })) { toast("This exact image is already fingerprinted.", "info"); return; }
      list.push(item); if (saveHashes(list)) { toast("Fingerprints created on this device. Nothing was uploaded.", "success"); renderHashList(); }
    } catch (e) { toast(e.message, "error"); }
  };
  $("#matchFile").onchange = async function () {
    var f = this.files[0]; this.value = ""; if (!f) return;
    var list = loadHashes(), out = $("#hashOut");
    if (!list.length) { out.innerHTML = '<div class="note">' + ic("info", "ic-sm") + "<span>You have no stored fingerprints yet.</span></div>"; return; }
    try {
      var r = await Promise.all([sha256File(f), dHashFile(f)]), best = null;
      list.forEach(function (x) { var d = hamming(r[1], x.dhash); if (!best || d < best.d) best = { d: d, x: x }; });
      var exact = list.some(function (x) { return x.sha256 === r[0]; });
      out.innerHTML = exact ? '<div class="note ok">' + ic("check", "ic-sm") + "<span><b>Exact match.</b> This is the same file as one you fingerprinted (SHA-256 identical).</span></div>"
        : best.d <= 10 ? '<div class="note warn">' + ic("alert", "ic-sm") + "<span><b>Looks similar</b> to a stored image (perceptual distance " + best.d + " of 64). It may be a resized or re-compressed copy, or a different image that looks alike.</span></div>"
        : '<div class="note">' + ic("info", "ic-sm") + "<span><b>No match.</b> Closest stored image differs by " + best.d + " of 64 bits. Heavily edited copies can still be missed.</span></div>";
    } catch (e) { toast(e.message, "error"); }
  };
}
function renderHashList() {
  var list = loadHashes(), el = $("#hashList"); if (!el) return;
  if (!list.length) { el.innerHTML = '<p class="muted small">No fingerprints stored on this device.</p>'; return; }
  el.innerHTML = "<h3>Stored on this device (" + list.length + ")</h3>" + list.map(function (x) {
    return '<div class="hash-row"><div><span class="small muted">' + esc(fmtDate(x.added)) + '</span><div class="mono small">SHA-256 ' + esc(shortHash(x.sha256)) + '</div><div class="mono small">dHash ' + esc(x.dhash) + '</div></div><button class="btn btn-ghost btn-sm" data-rmhash="' + x.id + '" type="button">Remove</button></div>';
  }).join("") + '<button class="btn btn-secondary btn-sm" id="rmAllHashes" type="button" style="margin-top:8px">Remove all fingerprints</button>';
  $$("[data-rmhash]", el).forEach(function (b) { b.onclick = function () { saveHashes(loadHashes().filter(function (x) { return String(x.id) !== b.getAttribute("data-rmhash"); })); renderHashList(); toast("Fingerprint removed from this device.", "success"); }; });
  $("#rmAllHashes").onclick = function () { try { localStorage.removeItem(HASH_KEY); } catch (e) {} renderHashList(); toast("All fingerprints removed from this device.", "success"); };
}

/* ======================= TRUSTED CONTACT ======================= */
VIEW_HOOKS.contacts = async function () {
  var el = $("#contactBody");
  try {
    var c = await api("/contacts"), h = "";
    if (!state.items.length) { try { state.items = await api("/vault"); } catch (e) {} }
    h += '<div class="panel panel-pad"><h2>What an alert contains</h2><div class="grid-2"><div><h3>Shared</h3><ul><li>Risk level of the record</li><li>Time it was recorded (UTC)</li><li>Its evidence fingerprint (hash)</li><li>The sender name you choose</li></ul></div>' +
      '<div><h3>Never shared</h3><ul><li>Message text or screenshots</li><li>Phone numbers, accounts or links</li><li>Your location</li><li>Your PIN or vault name</li></ul></div></div>' +
      '<p class="small muted">Alerts are only sent after you confirm on a screen that shows the exact message. SheShield never contacts anyone automatically.</p></div>';
    if (!c.smtp_configured) h += '<div class="note warn" style="margin:14px 0">' + ic("alert", "ic-sm") + "<span><b>Email sending is not set up on this server.</b> Trusted-contact alerts need SMTP settings (see README, Environment variables). Until then you cannot verify a contact or send an alert.</span></div>";
    if (!c.exists) {
      h += '<form class="panel panel-pad stack" id="fContact" style="margin-top:14px"><h2>Add a trusted contact</h2>' +
        '<div><label class="field" for="tcName">Their name</label><input class="input" id="tcName" required maxlength="80"></div>' +
        '<div><label class="field" for="tcEmail">Their email</label><input class="input" id="tcEmail" type="email" required></div>' +
        '<div><label class="field" for="tcSender">Name to show in the alert <span class="hint">optional</span></label><input class="input" id="tcSender" maxlength="60" placeholder="e.g. Asha"></div>' +
        '<p class="small muted">We email them a 6-digit code. They read it to you, and you enter it here. That proves the address is theirs. They are not told anything else.</p>' +
        '<div id="tcErr" class="note err" hidden></div><button class="btn btn-primary" type="submit"' + (c.smtp_configured ? "" : " disabled") + ">Send verification code</button></form>";
    } else if (!c.verified) {
      h += '<form class="panel panel-pad stack" id="fVerify" style="margin-top:14px"><h2>Verify ' + esc(c.name) + "</h2><p>We emailed a code to " + esc(c.email_masked) + ". It expires in 15 minutes.</p>" +
        '<div><label class="field" for="tcCode">6-digit code</label><input class="input mono" id="tcCode" inputmode="numeric" maxlength="6" required></div><div id="tcErr" class="note err" hidden></div>' +
        '<div class="btn-row"><button class="btn btn-primary" type="submit">Verify</button><button class="btn btn-ghost" id="tcRemove" type="button">Cancel and remove</button></div></form>';
    } else {
      h += '<div class="panel panel-pad" style="margin-top:14px"><div class="entry-top"><h2 style="margin:0">' + esc(c.name) + '</h2><span class="pill p-none">Verified</span></div><p class="muted">' + esc(c.email_masked) + (c.sender_name ? " · alerts say “" + esc(c.sender_name) + "”" : "") + "</p>" +
        '<div style="margin:12px 0">' + (state.items.length ? '<label class="field" for="tcRec">Record the alert refers to</label><select class="input" id="tcRec">' + recOptions() + '</select><p class="small muted" style="margin-top:6px">Only the risk level, time and fingerprint of this record are shared.</p>' : '<p class="small muted">Save some evidence first. An alert refers to a record\'s fingerprint.</p>') + '</div><div class="btn-row"><button class="btn btn-primary" id="tcAlert" type="button"' + (state.items.length ? "" : " disabled") + '>' + ic("alert", "ic-sm") + 'Alert ' + esc(c.name) + '</button><button class="btn btn-ghost" id="tcRemove" type="button">Remove contact</button></div></div>';
    }
    if (c.history && c.history.length) h += '<h2 style="margin:24px 0 8px">Alert history</h2>' + c.history.map(function (x) {
      var ok = x.status === "accepted_by_mail_server";
      return '<div class="panel panel-pad" style="margin-bottom:8px"><div class="entry-top"><span class="pill ' + (ok ? "p-info" : "p-high") + '">' + (ok ? "Accepted by mail server" : "Not sent") + "</span><time>" + esc(fmtDate(x.created_at)) + "</time></div><p class='small'>Record #" + esc(x.evidence_id) + " · " + esc(x.severity) + " · " + esc(x.detail) + "</p></div>";
    }).join("");
    el.innerHTML = h;
    var err = function (m) { var e = $("#tcErr"); e.innerHTML = ic("alert", "ic-sm") + "<span>" + esc(m) + "</span>"; e.hidden = false; };
    if ($("#fContact")) $("#fContact").onsubmit = async function (e) { e.preventDefault(); var b = e.target.querySelector("button[type=submit]"); setBusy(b, true, "Sending code…");
      try { await api("/contacts", "POST", { name: $("#tcName").value, email: $("#tcEmail").value, sender_name: $("#tcSender").value }); toast("Code sent.", "success"); VIEW_HOOKS.contacts(); } catch (x) { err(x.message); setBusy(b, false); } };
    if ($("#fVerify")) $("#fVerify").onsubmit = async function (e) { e.preventDefault(); try { await api("/contacts/verify", "POST", { code: $("#tcCode").value }); toast("Trusted contact verified.", "success"); VIEW_HOOKS.contacts(); } catch (x) { err(x.message); } };
    if ($("#tcRemove")) $("#tcRemove").onclick = async function () { if (await confirmDialog({ title: "Remove trusted contact?", html: "<p>They will no longer be available for alerts. Past alert history stays.</p>", confirm: "Remove", danger: true })) { await api("/contacts", "DELETE"); VIEW_HOOKS.contacts(); } };
    if ($("#tcAlert")) $("#tcAlert").onclick = function () { startAlert($("#tcRec") ? parseInt($("#tcRec").value, 10) : null); };
  } catch (e) { el.innerHTML = '<div class="note err">' + ic("alert", "ic-sm") + "<span>" + esc(e.message) + "</span></div>"; }
};
function recOptions() {
  var rank = { high: 3, medium: 2, low: 1, none: 0 }, best = null;
  state.items.forEach(function (i) { if (!best || rank[i.severity] >= rank[best.severity]) best = i; });
  return state.items.slice().reverse().map(function (i) { return "<option value='" + i.id + "'" + (best && i.id === best.id ? " selected" : "") + ">#" + i.id + " · " + esc(fmtDate(i.created_at)) + " · " + SEV[sevOf(i.severity)].label + "</option>"; }).join("");
}
async function startAlert(evidenceId) {
  var prep;
  try { prep = await api("/contacts/alert/prepare", "POST", { evidence_id: evidenceId }); }
  catch (e) { toast(e.message, "error"); if (/Add and verify/.test(e.message)) location.hash = "#/contacts"; return; }
  var ok = await confirmDialog({
    title: "Send this alert to " + prep.to_name + "?",
    html: "<p>This is the exact email that will be sent to <b>" + esc(prep.to) + "</b>. It expires in " + prep.expires_in + " seconds.</p><pre class='alert-preview'>" + esc(prep.message) + "</pre>" +
      "<p class='small'><b>Shared:</b> " + prep.shared.map(esc).join("; ") + ".<br><b>Not shared:</b> " + prep.not_shared.map(esc).join("; ") + ".</p>",
    confirm: "Send alert"
  });
  if (!ok) { try { await api("/contacts/alert/cancel", "POST", { confirm_token: prep.confirm_token }); } catch (e) {} toast("Cancelled. Nothing was sent.", "info"); return; }
  try {
    var r = await api("/contacts/alert/send", "POST", { confirm_token: prep.confirm_token });
    toast("Alert handed to the mail server. " + r.note, "success");
    if (location.hash === "#/contacts") VIEW_HOOKS.contacts();
  } catch (e) { toast("Alert not sent: " + e.message, "error"); }
}
document.addEventListener("click", function (e) { var b = e.target.closest("[data-alert]"); if (b) startAlert(parseInt(b.getAttribute("data-alert"), 10)); });

/* ======================= INSIGHTS ======================= */
function barList(obj, labels) {
  var keys = Object.keys(obj).sort(function (a, b) { return obj[b] - obj[a]; }), max = Math.max.apply(null, keys.map(function (k) { return obj[k]; }).concat([1]));
  if (!keys.length) return '<p class="muted small">Nothing yet.</p>';
  return '<div class="bars">' + keys.map(function (k) { return '<div class="bar-row"><span>' + esc((labels && labels[k]) || k) + '</span><div class="bar"><i style="width:' + (obj[k] / max * 100) + '%"></i></div><b>' + obj[k] + "</b></div>"; }).join("") + "</div>";
}
VIEW_HOOKS.insights = async function () {
  var el = $("#insightsBody");
  el.innerHTML = '<div class="skel skel-line"></div><div class="skel skel-line" style="width:60%"></div>';
  try {
    var d = await api("/insights");
    var max = Math.max.apply(null, d.trend_30d.map(function (t) { return t.count; }).concat([1]));
    var spark = '<svg viewBox="0 0 300 70" class="spark" role="img" aria-label="Messages analysed per day, last 30 days">' + d.trend_30d.map(function (t, i) { var hh = t.count / max * 60; return '<rect x="' + (i * 10 + 1) + '" y="' + (66 - hh) + '" width="8" height="' + Math.max(hh, 1) + '" rx="1.5"><title>' + t.date + ": " + t.count + "</title></rect>"; }).join("") + "</svg>";
    var ig = d.integrity;
    el.innerHTML = '<div class="note info" style="margin-bottom:16px">' + ic("info", "ic-sm") + "<span><b>Local vault statistics.</b> " + esc(d.scope) + "</span></div>" +
      '<div class="stat-row"><div class="panel panel-pad"><div class="lbl">Messages analysed</div><div class="big">' + d.total_analysed + '</div></div>' +
      '<div class="panel panel-pad"><div class="lbl">Saved as evidence</div><div class="big">' + d.total_saved + '</div></div>' +
      '<div class="panel panel-pad"><div class="lbl">Records verified</div><div class="big">' + (ig.percent_verified === null ? "–" : ig.percent_verified + "%") + '</div><div class="sub small muted">' + ig.records_verified + " of " + ig.records_total + " pass the integrity check</div></div>" +
      '<div class="panel panel-pad"><div class="lbl">Repeated identifiers</div><div class="big">' + d.related.repeated_identifiers + '</div><div class="sub small muted">' + d.related.related_incident_groups + " related incident group(s)</div></div></div>" +
      '<div class="grid-2" style="margin-top:18px"><div class="panel panel-pad"><h3>By category</h3>' + barList(d.by_category, CATEGORY) + '</div><div class="panel panel-pad"><h3>By language</h3>' + barList(d.by_language, LANG) + "</div></div>" +
      '<div class="panel panel-pad" style="margin-top:18px"><h3>Last 30 days</h3>' + spark + '<p class="small muted">Each bar is one day of analyses in this vault.</p></div>' +
      '<div class="panel panel-pad" style="margin-top:18px"><h3>By risk level</h3>' + barList(d.by_severity, { none: "No pattern", low: "Low", medium: "Concerning", high: "High" }) + "</div>";
  } catch (e) { el.innerHTML = '<div class="note err">' + ic("alert", "ic-sm") + "<span>" + esc(e.message) + "</span></div>"; }
};

/* ======================= SETTINGS & PRIVACY ======================= */
var DISCREET_KEY = "sheshield_discreet";
function discreetOn() { try { return localStorage.getItem(DISCREET_KEY) === "1"; } catch (e) { return false; } }
function applyDiscreet() {
  var on = discreetOn();
  document.body.classList.toggle("discreet", on);
  $$(".brand span").forEach(function (s) { s.textContent = on ? "Notes" : "SheShield"; });
  var icon = document.querySelector("link[rel=icon]");
  if (icon) icon.href = on ? "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect x='7' y='4' width='18' height='24' rx='3' fill='%23888'/%3E%3C/svg%3E" : state.faviconOriginal;
  document.title = on ? "Notes" : document.title.replace(/^Notes$/, "SheShield");
}
state.faviconOriginal = (document.querySelector("link[rel=icon]") || {}).href;
var _origRoute = window.route;
window.addEventListener("hashchange", function () { if (discreetOn()) document.title = "Notes"; });
document.addEventListener("keydown", function (e) {
  if (e.key === "Escape" && !document.querySelector("dialog[open]")) {
    var now = Date.now();
    if (state.lastEsc && now - state.lastEsc < 600) { location.replace("https://www.google.com/"); }
    state.lastEsc = now;
  }
});

VIEW_HOOKS.settings = function () {
  var el = $("#settingsBody"), cfg = state.config || {};
  var h = '<div class="panel panel-pad"><h2>How your data is protected</h2><ul class="plain">' +
    "<li><b>Encrypted at rest.</b> Evidence text and details are encrypted with AES-256-GCM. The key is wrapped by a key derived from your PIN with Argon2id. The server stores only the wrapped key, never the PIN.</li>" +
    "<li><b>Separate vaults.</b> Each vault name has its own key. One vault cannot read another.</li>" +
    "<li><b>Not encrypted:</b> record numbers, times, risk level and score, and the hash chain. These are needed to check integrity without unlocking each record.</li>" +
    "<li><b>Unlocked while you use it.</b> While your vault is open, the server holds its key in memory. It locks after " + esc((state.auth && state.auth.session_minutes) || 20) + " minutes of inactivity or when you press Lock.</li>" +
    "<li><b>Lockout.</b> After 5 wrong PINs, attempts are delayed for longer each time.</li>" +
    "<li><b>Your own machine matters.</b> Anyone with access to this computer while the vault is unlocked, or with a keylogger on it, can read your evidence. Encryption cannot protect against that.</li></ul></div>";
  h += '<form class="panel panel-pad stack" id="fPin" style="margin-top:16px"><h2>Change PIN</h2><div><label class="field" for="pOld">Current PIN</label><input class="input" id="pOld" type="password" autocomplete="current-password" required></div>' +
    '<div><label class="field" for="pNew">New PIN</label><input class="input" id="pNew" type="password" autocomplete="new-password" required minlength="6"></div><div id="pErr" class="note err" hidden></div><button class="btn btn-secondary" type="submit">Change PIN</button><p class="small muted">Your recovery code stays the same.</p></form>';
  h += '<div class="panel panel-pad" style="margin-top:16px"><h2>Discreet mode</h2><p>Shows a neutral name (“Notes”) and icon in the tab and header, and lets you press <b>Esc twice</b> to jump to another website.</p>' +
    '<label class="check"><input type="checkbox" id="chkDiscreet"' + (discreetOn() ? " checked" : "") + '> <span>Use discreet mode in this browser</span></label>' +
    '<div class="note warn" style="margin-top:10px">' + ic("alert", "ic-sm") + "<span><b>What it does not do:</b> it does not hide your browsing history, the address of this page, downloads, or the fact that this program is running. For stronger privacy use a private window and close it afterwards.</span></div></div>";
  h += '<div class="panel panel-pad" style="margin-top:16px"><h2>Voice notes</h2><p>' + (cfg.voice && cfg.voice.available ? "Voice transcription is installed on this server and runs locally." : esc((cfg.voice && cfg.voice.reason) || "Not available.")) + "</p></div>";
  h += '<div class="panel panel-pad" style="margin-top:16px"><h2>Session</h2><button class="btn btn-secondary" id="btnLock2" type="button">' + ic("lock", "ic-sm") + 'Lock now</button></div>';
  h += '<div class="panel panel-pad danger-zone" style="margin-top:16px"><h2>Panic wipe</h2><p>Permanently deletes this vault on this server: every record, analysis history, trusted contact, alert log, anchor reference and your encryption keys. It cannot be undone, and there is no recovery.</p>' +
    "<p class='small'><b>What it cannot erase:</b> blockchain transactions (public and permanent, though they contain only a fingerprint), PDF reports or screenshots you saved elsewhere, anything a trusted contact or email provider already received, backups of this computer, and browser history. Image fingerprints stored in this browser are also removed.</p>" +
    '<button class="btn btn-danger" id="btnWipe" type="button">Erase this vault…</button></div>';
  el.innerHTML = h;
  $("#chkDiscreet").onchange = function () { try { localStorage.setItem(DISCREET_KEY, this.checked ? "1" : "0"); } catch (e) {} applyDiscreet(); toast(this.checked ? "Discreet mode on." : "Discreet mode off.", "success"); };
  $("#btnLock2").onclick = function () { $("#btnLock").click(); };
  $("#fPin").onsubmit = async function (e) {
    e.preventDefault(); var b = e.target.querySelector("button[type=submit]"), er = $("#pErr"); er.hidden = true; setBusy(b, true, "Changing…");
    try { await api("/auth/change-pin", "POST", { old_pin: $("#pOld").value, new_pin: $("#pNew").value }); toast("PIN changed.", "success"); $("#pOld").value = $("#pNew").value = ""; }
    catch (x) { er.innerHTML = ic("alert", "ic-sm") + "<span>" + esc(x.message) + "</span>"; er.hidden = false; } finally { setBusy(b, false); }
  };
  $("#btnWipe").onclick = async function () {
    var ok = await confirmDialog({ title: "Erase this vault?", danger: true, confirm: "Continue",
      html: "<p>This deletes <b>everything</b> in vault “" + esc(state.auth.username) + "” on this server. It cannot be undone.</p><p class='small'>Blockchain transactions, saved PDFs and copies elsewhere are not erased.</p>" });
    if (!ok) return;
    var pin = await promptDialog({ title: "Confirm with your PIN", label: "PIN", type: "password", extra: "Type <b>DELETE MY VAULT</b> exactly to confirm.", phrase: true });
    if (!pin) return;
    try {
      var r = await api("/auth/wipe", "POST", { pin: pin.value, confirm: pin.phrase });
      try { localStorage.removeItem(HASH_KEY); } catch (e) {}
      state.auth = await api("/auth/status"); state.items = [];
      await confirmDialog({ title: "Vault erased", confirm: "OK", html: "<p>Deleted: " + Object.keys(r.wiped).map(function (k) { return r.wiped[k] + " " + k; }).join(", ") + ".</p><p class='small'><b>Not erased:</b></p><ul class='small'>" + r.not_erased.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul>" });
      showLock();
    } catch (x) { toast(x.message, "error"); }
  };
};
function promptDialog(o) {
  return new Promise(function (resolve) {
    var dlg = $("#dlg");
    $("#dlgTitle").textContent = o.title;
    $("#dlgBody").innerHTML = "<p>" + (o.extra || "") + '</p><label class="field" for="dlgIn">' + esc(o.label) + '</label><input class="input" id="dlgIn" type="' + (o.type || "text") + '" autocomplete="off">' +
      (o.phrase ? '<label class="field" for="dlgPhrase" style="margin-top:10px">Confirmation phrase</label><input class="input" id="dlgPhrase" autocomplete="off">' : "");
    var ok = $("#dlgOk"), cancel = $("#dlgCancel"), result = null;
    ok.textContent = "Erase vault"; ok.className = "btn btn-danger";
    ok.onclick = function () { result = { value: $("#dlgIn").value, phrase: o.phrase ? $("#dlgPhrase").value : "" }; dlg.close(); };
    cancel.onclick = function () { dlg.close(); };
    dlg.onclose = function () { ok.onclick = cancel.onclick = null; dlg.onclose = null; resolve(result); };
    dlg.showModal(); $("#dlgIn").focus();
  });
}

/* ======================= VOICE NOTE (inside Check a message) ======================= */
function mountVoice() {
  var host = $("#textWrap"); if (!host || $("#voicePanel")) return;
  var d = document.createElement("details"); d.id = "voicePanel"; d.className = "voice-panel";
  d.innerHTML = "<summary>" + ic("mic", "ic-sm") + "Voice note (optional)</summary><div id='voiceBody'></div>";
  host.parentNode.insertBefore(d, host);
  var cfg = state.config || {}, v = cfg.voice || {};
  var b = $("#voiceBody");
  if (!v.available) { b.innerHTML = '<div class="note">' + ic("info", "ic-sm") + "<span>" + esc(v.reason || "Voice transcription is not available.") + "</span></div>"; return; }
  b.innerHTML = '<p class="small">Transcribes a recording into text so it can be checked like any message.</p>' +
    '<div class="note info">' + ic("lock", "ic-sm") + "<span><b>Where it runs:</b> speech recognition (Whisper, " + esc(v.model) + ") runs on the computer that hosts SheShield, not on an outside service. The audio is written to a temporary file only while it is transcribed, then deleted. Only the transcript can be saved, never the audio.</span></div>" +
    '<label class="check" style="margin:10px 0"><input type="checkbox" id="voiceConsent"> <span>I agree to have this recording transcribed on this computer.</span></label>' +
    '<input type="file" id="voiceFile" accept="audio/*" disabled><div class="small muted" style="margin-top:6px">WAV, MP3, M4A, OGG, WEBM or FLAC, up to 15 MB. The first use may take a while as the model loads.</div>';
  $("#voiceConsent").onchange = function () { $("#voiceFile").disabled = !this.checked; };
  $("#voiceFile").onchange = async function () {
    var f = this.files[0]; this.value = ""; if (!f) return;
    var fd = new FormData(); fd.append("file", f); fd.append("consent", "yes");
    toast("Transcribing…", "info");
    try {
      var res = await fetch("/transcribe", { method: "POST", body: fd, credentials: "same-origin" });
      var j = await res.json().catch(function () { return {}; });
      if (res.status === 401) { state.auth = { authenticated: false }; showLock("expired"); return; }
      if (!res.ok) throw new Error(j.detail || "Transcription failed.");
      if (!j.transcript) { toast(j.note || "No speech detected.", "warn"); return; }
      $("#msg").value = j.transcript; $("#textWrap").hidden = false;
      state.image = null; state.fromVoice = true;
      state.analysis = Object.assign({ fromImage: false }, j.analysis, { identifiers: j.identifiers });
      state.analysisStale = false; $("#btnSave").disabled = false; renderResult(); revealResult();
      toast("Transcribed. " + j.note, "success");
    } catch (e) { toast(e.message, "error"); }
  };
}

/* ======================= START ======================= */
applyDiscreet();
VIEW_HOOKS.scan = function () { mountVoice(); };
window.sheshieldBoot();
