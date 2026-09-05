(() => {
  "use strict";

  const rawBase = window.X_UI_BASE_PATH || "/";
  const base = `${rawBase.startsWith("/") ? rawBase : `/${rawBase}`}`.replace(/\/*$/, "/");
  const probeUrl = `${base}panel/api/server/status`;
  const frameUrl = `${base}qos-speed/`;
  let launcher = null;
  let overlay = null;
  let frame = null;
  let lastFocus = null;
  let previousOverflow = "";

  function closePanel() {
    if (!overlay || overlay.hidden) return;
    overlay.hidden = true;
    document.body.classList.remove("xqos-panel-open");
    document.documentElement.style.overflow = previousOverflow;
    launcher?.setAttribute("aria-expanded", "false");
    lastFocus?.focus?.();
  }

  function openPanel() {
    if (!overlay || !launcher) return;
    lastFocus = document.activeElement;
    if (!frame.getAttribute("src")) frame.setAttribute("src", frameUrl);
    overlay.hidden = false;
    previousOverflow = document.documentElement.style.overflow;
    document.documentElement.style.overflow = "hidden";
    document.body.classList.add("xqos-panel-open");
    launcher.setAttribute("aria-expanded", "true");
    overlay.querySelector(".xqos-close")?.focus();
  }

  function mount() {
    if (launcher || !document.body) return;

    launcher = document.createElement("button");
    launcher.type = "button";
    launcher.className = "xqos-launcher";
    launcher.hidden = true;
    launcher.setAttribute("aria-haspopup", "dialog");
    launcher.setAttribute("aria-expanded", "false");
    launcher.innerHTML = '<span class="xqos-launcher-icon" aria-hidden="true">⇅</span><span>网速管理</span>';

    overlay = document.createElement("section");
    overlay.className = "xqos-overlay";
    overlay.hidden = true;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "节点网速管理");
    overlay.innerHTML = `
      <div class="xqos-window">
        <header class="xqos-window-head">
          <div><span class="xqos-live" aria-hidden="true"></span><strong>节点网速管理</strong><small>已使用 3x-ui 登录状态</small></div>
          <button class="xqos-close" type="button" aria-label="关闭网速管理">×</button>
        </header>
        <iframe class="xqos-frame" title="节点网速管理"></iframe>
      </div>`;
    frame = overlay.querySelector(".xqos-frame");

    launcher.addEventListener("click", openPanel);
    overlay.querySelector(".xqos-close").addEventListener("click", closePanel);
    overlay.addEventListener("mousedown", (event) => {
      if (event.target === overlay) closePanel();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closePanel();
    });
    document.body.append(launcher, overlay);
  }

  async function refreshAuthorization() {
    mount();
    try {
      const response = await fetch(probeUrl, {
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          Accept: "application/json",
          "X-Requested-With": "XMLHttpRequest",
        },
      });
      if (!response.ok) throw new Error("not authenticated");
      launcher.hidden = false;
    } catch (_error) {
      launcher.hidden = true;
      closePanel();
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", refreshAuthorization, { once: true });
  } else {
    refreshAuthorization();
  }
  window.setInterval(refreshAuthorization, 30000);
})();
