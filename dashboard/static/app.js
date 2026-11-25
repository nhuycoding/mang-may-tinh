/* KidGate Dashboard client helpers (Theme, i18n, CSRF-protected fetch, HTMX, toasts) */

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") || "" : "";
}

function tr(key, vars = {}) {
  const dict = window.KIDGATE_I18N || {};
  let text = typeof dict[key] === "string" ? dict[key] : key;
  for (const [k, v] of Object.entries(vars)) {
    text = text.replaceAll(`{${k}}`, String(v));
  }
  return text;
}

function toggleTheme() {
  const root = document.documentElement;
  const isDark = root.classList.toggle("dark");
  localStorage.setItem("kidgate_theme", isDark ? "dark" : "light");
  window.dispatchEvent(new CustomEvent("kidgate:theme-changed", { detail: { dark: isDark } }));
}

function setLanguage(lang) {
  if (lang !== "vi" && lang !== "en") return;
  localStorage.setItem("kidgate_lang", lang);
  document.cookie = `kidgate_lang=${lang}; path=/; max-age=31536000; SameSite=Lax`;
  const url = new URL(window.location.href);
  url.searchParams.delete("lang");
  window.location.href = url.toString();
}

// Automatically attach X-CSRF-Token to all HTMX requests
document.addEventListener("htmx:configRequest", (evt) => {
  const token = getCsrfToken();
  if (token) {
    evt.detail.headers["X-CSRF-Token"] = token;
  }
});

function showToast(message, kind = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const colors = {
    success: "bg-emerald-600 text-white",
    error: "bg-rose-600 text-white",
    info: "bg-slate-800 dark:bg-slate-700 text-white",
    warning: "bg-amber-500 text-slate-950",
  };
  const el = document.createElement("div");
  el.className = `px-4 py-3 rounded-xl shadow-lg text-sm font-medium transition-all duration-300 ${colors[kind] || colors.info}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.classList.add("opacity-0", "translate-y-2");
    setTimeout(() => el.remove(), 300);
  }, 3800);
}

async function refreshCsrfToken() {
  try {
    const resp = await fetch("/auth/me", { credentials: "same-origin" });
    if (resp.status === 401) {
      window.location.href = "/login";
      return "";
    }
    if (!resp.ok) return "";
    const data = await resp.json();
    if (data && data.csrf_token) {
      const meta = document.querySelector('meta[name="csrf-token"]');
      if (meta) meta.setAttribute("content", data.csrf_token);
      return data.csrf_token;
    }
  } catch (_) {
    // Ignore
  }
  return "";
}

async function apiFetch(url, options = {}, _retried = false) {
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    options.headers || {}
  );
  const method = (options.method || "GET").toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    let token = getCsrfToken();
    if (!token) {
      token = await refreshCsrfToken();
    }
    headers["X-CSRF-Token"] = token;
  }
  const resp = await fetch(url, Object.assign({}, options, { headers, credentials: "same-origin" }));
  let data = null;
  try {
    data = await resp.json();
  } catch (_) {
    data = null;
  }
  if (!resp.ok) {
    const detail = (data && data.detail) ? data.detail : `HTTP ${resp.status}`;
    if (
      !_retried &&
      resp.status === 403 &&
      typeof detail === "string" &&
      detail.toLowerCase().includes("csrf")
    ) {
      const freshToken = await refreshCsrfToken();
      if (freshToken) {
        return apiFetch(url, options, true);
      }
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

async function logoutUser() {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } catch (_) {
    // Ignore errors on logout
  }
  window.location.href = "/login";
}
