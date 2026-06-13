/**
 * DeepTrace — Content Script v9 (CONTEXT-SAFE)
 *
 * FIX: All chrome.* API calls are wrapped in try/catch to handle
 * "Extension context invalidated" errors. This happens when:
 *  - The extension was reloaded at chrome://extensions
 *  - But the tab wasn't refreshed (F5)
 * Old content scripts keep running but can't call chrome APIs anymore.
 * We catch those errors and show a "please refresh" message.
 */

const MAX_CHARS = 5000;
let floatBtn  = null;
let modePopup = null;
let btnEnabled = true;
let contextValid = true; // Track whether we can use chrome APIs

// ── Safe wrapper for chrome API calls ─────────────────────────────────────
function safeChromeCall(fn) {
  if (!contextValid) return;
  try {
    return fn();
  } catch (e) {
    if (e.message && e.message.includes("Extension context invalidated")) {
      contextValid = false;
      removeBtn();
      removeModePopup();
      showToast("⚠ DeepTrace was reloaded. Please refresh this page (F5).");
    }
  }
}

// ── Initialize ────────────────────────────────────────────────────────────
safeChromeCall(() => {
  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, s => {
    if (chrome.runtime.lastError) return;
    btnEnabled = (s && s.showFloatBtn !== false);
  });
});

let keepAlivePort = null;

function isLikelyUrl(str) {
  const s = str.trim();
  return /^https?:\/\//i.test(s) ||
         /^ftp:\/\//i.test(s) ||
         /^www\./i.test(s) ||
         /^[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(\/|$)/.test(s);
}

// ── Pre-wake service worker ───────────────────────────────────────────────
function preWakeServiceWorker() {
  safeChromeCall(() => {
    if (keepAlivePort) {
      try { keepAlivePort.disconnect(); } catch (_) {}
    }
    keepAlivePort = chrome.runtime.connect({ name: "dt-prewake" });
    keepAlivePort.onDisconnect.addListener(() => { keepAlivePort = null; });
  });
}

// ── Float button ──────────────────────────────────────────────────────────
function createBtn() {
  if (floatBtn) return;
  if (!contextValid) return; // Don't show button if context is dead

  preWakeServiceWorker();

  floatBtn = document.createElement("button");
  floatBtn.id = "dt-float-btn";
  floatBtn.innerHTML =
    `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      stroke-width="2.5" stroke-linecap="round">
      <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
    </svg><span>DeepTrace</span>`;
  floatBtn.addEventListener("click", onBtnClick);
  document.body.appendChild(floatBtn);
}

function removeBtn() {
  if (floatBtn) { floatBtn.remove(); floatBtn = null; }
}

function posBtn(x, y) {
  if (!floatBtn) return;
  floatBtn.style.left = Math.min(x + 12, window.innerWidth  - 160) + "px";
  floatBtn.style.top  = Math.min(y + 12, window.innerHeight -  90) + "px";
}

// ── Mode popup ────────────────────────────────────────────────────────────
function createModePopup(anchorX, anchorY, selectedText) {
  removeModePopup();
  if (!contextValid) return;

  preWakeServiceWorker();

  const isUrl = isLikelyUrl(selectedText.trim());

  const options = isUrl
    ? [
        { mode: "url",  icon: "🔗", label: "Check URL",    sub: "Phishing & malware" },
        { mode: "both", icon: "🔍", label: "Full Scan",     sub: "URL + text analysis" },
      ]
    : [
        { mode: "text",    icon: "🎣", label: "Scam/Phishing", sub: "Detect scam language" },
        { mode: "ai",      icon: "🤖", label: "AI Detection",  sub: "Human vs AI-written" },
        { mode: "text_ai", icon: "🔍", label: "Both",          sub: "Phishing + AI check", highlight: true },
      ];

  const btnsHtml = options.map(o => `
    <button class="dt-mp-btn${o.highlight ? " dt-mp-hl" : ""}" data-mode="${o.mode}">
      <span class="dt-mp-icon">${o.icon}</span>
      <div class="dt-mp-text">
        <span class="dt-mp-lbl">${o.label}</span>
        <span class="dt-mp-sub">${o.sub}</span>
      </div>
    </button>`).join("");

  modePopup = document.createElement("div");
  modePopup.id = "dt-mode-popup";
  modePopup.innerHTML = `
    <div class="dt-mp-header">
      <span class="dt-mp-type">${isUrl ? "🔗 URL selected" : "📝 Text selected"}</span>
      <span class="dt-mp-q">Choose scan type:</span>
    </div>
    <div class="dt-mp-btns">${btnsHtml}</div>
    <div class="dt-mp-hint">✓ Click a scan type to analyze automatically</div>
  `;

  const left = Math.max(8, Math.min(anchorX, window.innerWidth - 230));
  const top  = Math.max(8, anchorY - (isUrl ? 135 : 185));
  modePopup.style.left = left + "px";
  modePopup.style.top  = top  + "px";

  modePopup.querySelectorAll(".dt-mp-btn").forEach(btn => {
    btn.addEventListener("click", e => {
      e.stopPropagation();
      e.preventDefault();
      const mode = btn.dataset.mode;
      const capturedText = selectedText;

      queueAnalysis(capturedText, mode, isUrl);
      removeModePopup();
      removeBtn();
    });
  });

  document.body.appendChild(modePopup);
}

function removeModePopup() {
  if (modePopup) { modePopup.remove(); modePopup = null; }
}

// ── Selection events ──────────────────────────────────────────────────────
document.addEventListener("mouseup", () => {
  if (!btnEnabled || !contextValid) return;
  setTimeout(() => {
    try {
      const sel  = window.getSelection();
      const text = sel ? sel.toString().trim() : "";
      if (text.length >= 4) {
        const rect = sel.getRangeAt(0).getBoundingClientRect();
        createBtn();
        posBtn(rect.right + window.scrollX, rect.bottom + window.scrollY);
      } else {
        removeBtn();
        removeModePopup();
      }
    } catch (_) {
      // getRangeAt can throw if selection is collapsed
    }
  }, 60);
});

document.addEventListener("mousedown", e => {
  if (floatBtn  && !floatBtn.contains(e.target))  removeBtn();
  if (modePopup && !modePopup.contains(e.target)) removeModePopup();
});

document.addEventListener("keydown", () => {
  removeBtn();
  removeModePopup();
});

// ── Button click ──────────────────────────────────────────────────────────
function onBtnClick(e) {
  e.stopPropagation();
  e.preventDefault();
  const text = (window.getSelection()?.toString().trim() || "").slice(0, MAX_CHARS);
  if (!text) return;
  const rect = floatBtn.getBoundingClientRect();
  createModePopup(rect.left + window.scrollX, rect.top + window.scrollY, text);
}

// ── Queue analysis ────────────────────────────────────────────────────────
function queueAnalysis(selectedText, mode, isUrl) {
  let payload;
  if (isUrl && (mode === "url" || mode === "both")) {
    payload = { url: selectedText, mode, source: "selection" };
  } else {
    payload = { text: selectedText, mode, source: "selection" };
  }

  // Write directly to session storage
  safeChromeCall(() => {
    chrome.storage.session.set({ pendingAnalysis: payload });
  });

  // Tell service worker
  safeChromeCall(() => {
    chrome.runtime.sendMessage({ type: "DT_ANALYZE", payload }, (response) => {
      if (chrome.runtime.lastError) return;
      if (response && response.opened) {
        showToast("✓ DeepTrace panel opened — analyzing…");
      } else {
        showToast("✓ Queued — click the 🔍 DeepTrace icon in the toolbar!");
      }
    });
  });
}

// ── Toast notification ────────────────────────────────────────────────────
function showToast(msg) {
  const old = document.getElementById("dt-toast");
  if (old) old.remove();
  const t = document.createElement("div");
  t.id = "dt-toast";
  t.textContent = msg;
  t.style.cssText = `
    position:fixed; bottom:20px; right:20px; z-index:2147483647;
    background:rgba(10,12,35,0.97); color:#a0b4ff;
    border:1px solid rgba(100,120,255,0.35); border-radius:10px;
    padding:11px 16px; font-family:-apple-system,sans-serif;
    font-size:12.5px; font-weight:500; max-width:300px;
    box-shadow:0 8px 32px rgba(0,0,0,0.6);
    animation:dt-toast-in 0.2s ease;
  `;
  document.head.insertAdjacentHTML("beforeend",
    `<style>@keyframes dt-toast-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}</style>`);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}
