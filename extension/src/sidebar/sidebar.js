/**
 * DeepTrace — Sidebar v8 (MODE-AWARE RENDERING)
 *
 * FIXES:
 * 1. renderResult() now shows/hides sections based on the analysis mode:
 *    - "text" (Phishing) → Risk bar, keywords, explanation. NO AI section.
 *    - "ai" (AI only) → AI vs Human bars. NO risk bar, no keywords.
 *    - "text_ai" (Both) → Everything.
 *    - "url" → Risk bar, keywords, explanation. NO AI section.
 *
 * 2. Three payload detection mechanisms: onChanged, polling, visibilitychange.
 *
 * 3. processPayload: injects text/URL into inputs, selects correct tab/mode,
 *    and auto-analyzes immediately.
 */

const txt     = document.getElementById("txt");
const urlinp  = document.getElementById("urlinp");
const cnum    = document.getElementById("cnum");
const btnTxt  = document.getElementById("btn-text");
const btnUrl  = document.getElementById("btn-url");
const loadEl  = document.getElementById("loading");
const errEl   = document.getElementById("errcard");
const vcardEl = document.getElementById("vcard");
const emptyEl = document.getElementById("empty");

let textMode = "text_ai";
let processingPayload = false;

// ── Reusable: process a pending analysis payload ──────────────────────────
function processPayload(payload) {
  if (processingPayload) return;
  processingPayload = true;
  pollCount = MAX_POLLS; // stop polling

  // Populate input fields so user sees what was analyzed
  if (payload.url) {
    urlinp.value = payload.url;
    switchTab("url");
  }
  if (payload.text) {
    txt.value = payload.text;
    cnum.textContent = payload.text.length;
    switchTab("text");
    // Sync mode chips with the selected mode
    if (payload.mode && ["text_ai", "text", "ai"].includes(payload.mode)) {
      textMode = payload.mode;
      document.querySelectorAll(".mchip").forEach(c => {
        c.classList.toggle("on", c.dataset.mode === textMode);
      });
    }
  }

  // Run analysis automatically
  showLoad();
  chrome.runtime.sendMessage({ type: "ANALYZE_REQUEST", payload }, apiRes => {
    hideLoad();
    processingPayload = false;
    if (chrome.runtime.lastError) return showErr("Extension error. Try reloading.");
    if (!apiRes)        return showErr("No response. Is uvicorn running on port 8000?");
    if (apiRes.error)   return showErr(apiRes.error);
    if (!apiRes.result) return showErr("Empty response from API.");
    renderResult(apiRes.result);
  });
}

// ── Mechanism 1: Instant detection via storage.onChanged ──────────────────
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.pendingAnalysis && changes.pendingAnalysis.newValue) {
    const payload = changes.pendingAnalysis.newValue;
    chrome.storage.session.remove("pendingAnalysis");
    processPayload(payload);
  }
});

// ── Mechanism 2: Polling fallback ─────────────────────────────────────────
let pollCount = 0;
const MAX_POLLS = 20;

function pollPending() {
  chrome.runtime.sendMessage({ type: "GET_PENDING" }, res => {
    if (chrome.runtime.lastError) return;
    if (res && res.payload) {
      processPayload(res.payload);
    } else {
      pollCount++;
      if (pollCount < MAX_POLLS) setTimeout(pollPending, 500);
    }
  });
}
pollPending();

// ── Mechanism 3: Visibility change ────────────────────────────────────────
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && !processingPayload) {
    pollCount = 0;
    pollPending();
  }
});

// ── Tab switching ─────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll(".tab").forEach(b => b.classList.remove("on"));
  document.querySelectorAll(".panel").forEach(p => p.classList.remove("on"));
  const btn = document.querySelector(`.tab[data-tab="${name}"]`);
  const pnl = document.getElementById(`tab-${name}`);
  if (btn) btn.classList.add("on");
  if (pnl) pnl.classList.add("on");
}

document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("on"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("on"));
    btn.classList.add("on");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("on");
  });
});

// ── Mode chips — auto-re-analyze on click ─────────────────────────────────
document.querySelectorAll(".mchip").forEach(chip => {
  chip.addEventListener("click", () => {
    document.querySelectorAll(".mchip").forEach(c => c.classList.remove("on"));
    chip.classList.add("on");
    textMode = chip.dataset.mode;

    // If there's text, immediately re-analyze with the new mode
    const t = txt.value.trim();
    if (t) {
      runManual({ text: t, mode: textMode, source: "manual" });
    }
  });
});

txt.addEventListener("input", () => { cnum.textContent = txt.value.length; });

// ── Manual buttons ────────────────────────────────────────────────────────
btnTxt.addEventListener("click", () => {
  const t = txt.value.trim();
  if (!t) return showErr("Please paste some text to analyze.");
  runManual({ text: t, mode: textMode, source: "manual" });
});

btnUrl.addEventListener("click", () => {
  const u = urlinp.value.trim();
  if (!u) return showErr("Please enter a URL.");
  runManual({ url: u, mode: "url", source: "manual" });
});

function runManual(payload) {
  showLoad();
  chrome.runtime.sendMessage({ type: "ANALYZE_REQUEST", payload }, res => {
    hideLoad();
    if (chrome.runtime.lastError) return showErr("Extension error: " + chrome.runtime.lastError.message);
    if (!res)        return showErr("No response. Is uvicorn running on port 8000?");
    if (res.error)   return showErr(res.error);
    if (!res.result) return showErr("Empty response from API.");
    renderResult(res.result);
  });
}

// ── Render result (MODE-AWARE) ────────────────────────────────────────────
//
// Which sections show for each mode:
//   "text" (Phishing)  → Verdict, Risk bar, Keywords, Explanation, Suggestions
//   "ai"   (AI only)   → Verdict, AI vs Human bars, Explanation, Suggestions
//   "text_ai" (Both)   → Everything
//   "url"              → Verdict, Risk bar, Keywords, Explanation, Suggestions
//   "both"             → Everything
//
function renderResult(r) {
  emptyEl.style.display = "none";
  errEl.classList.remove("on");
  vcardEl.classList.add("on");

  const { verdict, label, confidence, summary, risk, suggestions,
          url_module, text_module, ai_module, ai_visual, mode, truncated } = r;

  // Determine which sections to show based on the analysis mode
  const showRisk = mode !== "ai";               // Risk bar for phishing/URL modes
  const showAI   = mode !== "text" && mode !== "url"; // AI section for AI/Both modes

  // ── Verdict header ──────────────────────────────────────────────────
  const icons    = { safe: "✅", suspicious: "⚠️", dangerous: "🚨" };
  const labelMap = {
    legitimate:   { txt: "Legitimate",      cls: "safe" },
    phishing:     { txt: "Phishing / Scam", cls: verdict === "dangerous" ? "dangerous" : "suspicious" },
    ai_generated: { txt: "AI-Generated",    cls: "ai-gen" },
    unknown:      { txt: "Unknown",         cls: "suspicious" },
  };
  const lm     = labelMap[label] || labelMap.unknown;
  const orbCls = lm.cls === "ai-gen" ? "ai" : verdict;

  document.getElementById("vorb").textContent  = icons[verdict] || "🔍";
  document.getElementById("vorb").className     = "vorb " + orbCls;
  document.getElementById("vtitle").textContent = lm.txt;
  document.getElementById("vtitle").className   = "vtitle " + lm.cls;
  document.getElementById("vsub").textContent   =
    Math.round(confidence * 100) + "% confidence" + (truncated ? " · text truncated" : "");
  document.getElementById("vsummary").textContent = summary;

  // ── Risk meter (only for Phishing / URL / Both modes) ───────────────
  const riskWrap = document.getElementById("risk-wrap");
  if (showRisk && risk) {
    const pill = document.getElementById("risk-pill");
    const bar  = document.getElementById("risk-bar");
    pill.textContent = risk.label;
    pill.className   = "risk-pill " + risk.color;
    bar.className    = "risk-bar "  + risk.color;
    bar.style.width  = "0%";
    requestAnimationFrame(() => requestAnimationFrame(() => {
      bar.style.width = risk.score_pct + "%";
    }));
    riskWrap.style.display = "block";
  } else {
    riskWrap.style.display = "none";
  }

  // ── AI visualization (only for AI / Both modes) ─────────────────────
  const aiSec = document.getElementById("ai-section");
  if (showAI && ai_visual) {
    document.getElementById("human-pct-big").textContent = ai_visual.human_pct + "%";
    document.getElementById("ai-pct-big").textContent    = ai_visual.ai_pct    + "%";
    document.getElementById("human-bar-lbl").textContent = ai_visual.human_label;
    document.getElementById("ai-bar-lbl").textContent    = ai_visual.ai_label;
    document.getElementById("ai-expl").textContent =
      (ai_module && ai_module.explanation) ? ai_module.explanation : "";
    const hb = document.getElementById("human-bar");
    const ab = document.getElementById("ai-bar");
    hb.style.width = "0%"; ab.style.width = "0%";
    requestAnimationFrame(() => requestAnimationFrame(() => {
      hb.style.width = ai_visual.human_pct + "%";
      ab.style.width = ai_visual.ai_pct    + "%";
    }));
    aiSec.style.display = "block";
  } else {
    aiSec.style.display = "none";
  }

  // ── Keywords (for Phishing / URL / Both modes) ──────────────────────
  const kwSec  = document.getElementById("kw-section");
  const kwList = document.getElementById("kw-list");
  const allKw  = [
    ...((text_module && text_module.keywords) || []),
    ...((url_module  && url_module.keywords)  || []),
  ].filter((v, i, a) => a.indexOf(v) === i).slice(0, 10);
  if (showRisk && allKw.length > 0) {
    kwList.innerHTML = allKw.map(k => `<span class="kw-tag">${esc(k)}</span>`).join("");
    kwSec.style.display = "block";
  } else {
    kwSec.style.display = "none";
  }

  // ── Explanation ─────────────────────────────────────────────────────
  const explSec  = document.getElementById("expl-section");
  const explText = document.getElementById("expl-text");
  let expl = "";
  if (showRisk) {
    expl = (url_module  && url_module.explanation)  ||
           (text_module && text_module.explanation) || "";
  }
  if (showAI && !expl) {
    expl = (ai_module && ai_module.explanation) || "";
  }
  if (expl) {
    explText.textContent  = expl;
    explSec.style.display = "block";
  } else {
    explSec.style.display = "none";
  }

  // ── Suggestions ─────────────────────────────────────────────────────
  const suggSec  = document.getElementById("sugg-section");
  const suggList = document.getElementById("sugg-list");
  if (suggestions && suggestions.length > 0) {
    suggList.innerHTML = suggestions
      .map(s => `<div class="sugg-row"><div class="sugg-dot"></div><span>${esc(s)}</span></div>`)
      .join("");
    suggSec.style.display = "block";
  } else {
    suggSec.style.display = "none";
  }
}

// ── UI helpers ────────────────────────────────────────────────────────────
function showLoad() {
  loadEl.classList.add("on");
  vcardEl.classList.remove("on");
  errEl.classList.remove("on");
  emptyEl.style.display = "none";
  btnTxt.disabled = btnUrl.disabled = true;
}
function hideLoad() {
  loadEl.classList.remove("on");
  btnTxt.disabled = btnUrl.disabled = false;
}
function showErr(msg) {
  hideLoad();
  emptyEl.style.display = "none";
  vcardEl.classList.remove("on");
  errEl.textContent = "⚠ " + msg;
  errEl.classList.add("on");
}
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
