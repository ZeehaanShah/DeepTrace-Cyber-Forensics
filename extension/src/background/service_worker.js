/**
 * DeepTrace — Service Worker v8 (PRE-WAKE + POPUP FALLBACK)
 *
 * RELIABILITY STRATEGY (3 layers):
 *
 *  Layer 1 — PRE-WAKE: Content script connects a port when the float button
 *            appears, waking this worker 1-5 seconds before the user clicks.
 *            When DT_ANALYZE arrives, the worker is already running, so
 *            sidePanel.open() fires within ~1ms (gesture still valid).
 *
 *  Layer 2 — POPUP WINDOW FALLBACK: If sidePanel.open() fails, open
 *            sidebar.html in a chrome.windows.create() popup window.
 *            This NEVER requires a user gesture and always works.
 *
 *  Layer 3 — BADGE + TOOLBAR: If all else fails, show a badge "!" on the
 *            toolbar icon. User clicks it → sidebar opens via
 *            openPanelOnActionClick: true.
 *
 *  Context menu: ALWAYS works (has guaranteed user gesture).
 */

const API_BASE  = "http://localhost:8000/api/v1";
const MAX_CHARS = 5000;

// ── TOP-LEVEL SETUP (runs every time the worker script executes) ──────────
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
chrome.storage.session.setAccessLevel({
  accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS"
}).catch(() => {});

// ── On install ──────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id:       "dt-analyze",
      title:    "Analyze with DeepTrace",
      contexts: ["selection", "link", "page"],
    });
  });

  chrome.storage.local.set({
    apiUrl:        API_BASE,
    autoAnalyze:   false,
    showFloatBtn:  true,
  });
});

// ── Pre-wake port handler ─────────────────────────────────────────────────
// Content script connects this port when the float button appears.
// This keeps the service worker alive so that when the user clicks a mode,
// sidePanel.open() can be called while the gesture is still valid.
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === "dt-prewake") {
    // Just hold the connection open — no messages needed
    port.onDisconnect.addListener(() => {});
  }
});

// ── Context menu ──────────────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "dt-analyze") return;

  let payload;
  if (info.linkUrl) {
    payload = { url: info.linkUrl, mode: "url", source: "context_menu" };
  } else if (info.selectionText) {
    const sel   = info.selectionText.trim().slice(0, MAX_CHARS);
    const isUrl = /^https?:\/\/|^www\.|^ftp:\/\//i.test(sel) ||
                  /^[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(\/|$)/.test(sel);
    payload = isUrl
      ? { url: sel,  mode: "url",     source: "context_menu" }
      : { text: sel, mode: "text_ai", source: "context_menu" };
  } else {
    payload = { url: tab.url, mode: "url", source: "context_menu" };
  }

  await chrome.storage.session.set({ pendingAnalysis: payload });

  // Context menu always has user gesture — sidePanel.open() always works
  try {
    await chrome.sidePanel.open({ tabId: tab.id });
    chrome.action.setBadgeText({ text: "" });
  } catch (_) {}
});

// ── Message routing ───────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {

  if (msg.type === "ANALYZE_REQUEST") {
    callApi(msg.payload).then(reply);
    return true;
  }

  // From content script — try to open sidebar automatically
  if (msg.type === "DT_ANALYZE") {
    // Store payload first
    chrome.storage.session.set({ pendingAnalysis: msg.payload });

    if (sender.tab && sender.tab.id) {
      // Layer 1: Try sidePanel.open() (works if worker was pre-woken)
      chrome.sidePanel.open({ tabId: sender.tab.id })
        .then(() => {
          // SUCCESS — sidebar is opening
          chrome.action.setBadgeText({ text: "" });
          reply({ ok: true, opened: true });
        })
        .catch(() => {
          // Layer 2: Popup window fallback (ALWAYS works, no gesture needed)
          chrome.windows.create({
            url:    chrome.runtime.getURL("src/sidebar/sidebar.html"),
            type:   "popup",
            width:  420,
            height: 700,
            left:   Math.max(0, (screen?.availWidth || 1200) - 440),
            top:    50,
          }).then(() => {
            chrome.action.setBadgeText({ text: "" });
            reply({ ok: true, opened: true });
          }).catch(() => {
            // Layer 3: Badge indicator — user clicks toolbar icon
            chrome.action.setBadgeText({ text: "!" });
            chrome.action.setBadgeBackgroundColor({ color: "#6c63ff" });
            reply({ ok: true, opened: false });
          });
        });
    } else {
      reply({ ok: true, opened: false });
    }

    return true; // keep channel open for async reply
  }

  if (msg.type === "GET_PENDING") {
    chrome.storage.session.get("pendingAnalysis", (data) => {
      if (data && data.pendingAnalysis) {
        chrome.storage.session.remove("pendingAnalysis");
        chrome.action.setBadgeText({ text: "" });
        reply({ payload: data.pendingAnalysis });
      } else {
        reply({ payload: null });
      }
    });
    return true;
  }

  if (msg.type === "GET_SETTINGS") {
    chrome.storage.local.get(["apiUrl", "autoAnalyze", "showFloatBtn"], reply);
    return true;
  }

  if (msg.type === "SAVE_SETTINGS") {
    chrome.storage.local.set(msg.settings, () => reply({ ok: true }));
    return true;
  }
});

// ── API caller ────────────────────────────────────────────────────────────
async function callApi(payload) {
  try {
    const s    = await chrome.storage.local.get("apiUrl");
    const base = (s.apiUrl || API_BASE).replace(/\/$/, "");

    const body = {};
    if (payload.text) body.text = payload.text;
    if (payload.url)  body.url  = payload.url;
    body.mode   = payload.mode   || "both";
    body.source = payload.source || "unknown";

    const res = await fetch(`${base}/analyze`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });

    if (!res.ok) {
      const e = await res.text();
      return { error: `API ${res.status}: ${e.slice(0, 200)}` };
    }
    return { success: true, result: await res.json() };

  } catch (err) {
    return err.message?.includes("fetch")
      ? { error: "Cannot reach backend. Make sure uvicorn is running on port 8000." }
      : { error: err.message };
  }
}

// ── Auto-analyze on navigation ────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url || tab.url.startsWith("chrome://")) return;
  const s = await chrome.storage.local.get("autoAnalyze");
  if (!s.autoAnalyze) return;
  const res = await callApi({ url: tab.url, mode: "url", source: "auto" });
  if (res.success)
    chrome.storage.session.set({ lastAutoResult: res.result });
});
