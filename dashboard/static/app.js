/* OGK Dashboard client helpers (CSRF-protected fetch, HTMX header injection, toasts, 7x48 schedule) */

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") || "" : "";
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
    info: "bg-slate-800 text-white",
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

async function apiFetch(url, options = {}) {
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    options.headers || {}
  );
  const method = (options.method || "GET").toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    headers["X-CSRF-Token"] = getCsrfToken();
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
