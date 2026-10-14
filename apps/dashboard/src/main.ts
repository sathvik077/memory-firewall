/** Dashboard entry point: tabs, identity switching, health and theme. */
import { ApiError, api, setToken, type Principal } from "./api.js";
import { badge, clear, el, errorBox, toast } from "./dom.js";
import { renderAttackLab } from "./panes/attacklab.js";
import { renderConflicts } from "./panes/conflicts.js";
import { renderIngest } from "./panes/ingest.js";
import { renderLedger } from "./panes/ledger.js";
import { renderQuarantine } from "./panes/quarantine.js";
import { renderSources } from "./panes/sources.js";
import { renderTimeMachine } from "./panes/timemachine.js";
import { renderTrace } from "./panes/trace.js";

interface Pane {
  id: string;
  label: string;
  render: (root: HTMLElement, onChange: () => void) => Promise<void> | void;
  /** Badge count. Only polled when the current role satisfies `needsRole`. */
  count?: () => Promise<number | null>;
  /** Minimum role the count endpoint requires. Polling it as a lesser role would 403. */
  needsRole?: "reviewer" | "admin";
}

const PANES: Pane[] = [
  { id: "ingest", label: "Ingest & scan", render: (root) => renderIngest(root) },
  { id: "sources", label: "Trust map", render: renderSources },
  {
    id: "quarantine",
    label: "Quarantine",
    render: renderQuarantine,
    count: async () => (await api.quarantine()).count,
    needsRole: "reviewer",
  },
  {
    id: "conflicts",
    label: "Conflicts",
    render: renderConflicts,
    count: async () => (await api.conflicts()).items.filter((c) => c.status === "needs_review").length,
  },
  { id: "trace", label: "Retrieval trace", render: (root) => renderTrace(root) },
  { id: "ledger", label: "Memory ledger", render: (root) => renderLedger(root) },
  { id: "timemachine", label: "Time machine", render: renderTimeMachine },
  { id: "attacklab", label: "Attack lab", render: (root) => renderAttackLab(root) },
];

const paneRoot = document.getElementById("pane-root") as HTMLElement;
const tabsRoot = document.getElementById("tabs") as HTMLElement;
const principalSelect = document.getElementById("principal-select") as HTMLSelectElement;
const principalField = document.getElementById("principal-field") as HTMLElement;
const tokenField = document.getElementById("token-field") as HTMLElement;
const tokenInput = document.getElementById("token-input") as HTMLInputElement;
const tokenApply = document.getElementById("token-apply") as HTMLButtonElement;
const identityBadge = document.getElementById("identity-badge") as HTMLElement;
const healthBadge = document.getElementById("health-badge") as HTMLElement;
const footerVersions = document.getElementById("footer-versions") as HTMLElement;
const themeToggle = document.getElementById("theme-toggle") as HTMLButtonElement;

let activePane = PANES[0]!.id;
let principals: Principal[] = [];
let currentRole = "reader";

const ROLE_RANK: Record<string, number> = { reader: 0, reviewer: 1, admin: 2 };

/** True when the signed-in role is at least `role`. Used to avoid polling endpoints that would
 *  403 for this principal — a reader seeing console 403s from the UI's own badge refresher is a
 *  bug, not a security finding. */
function hasRole(role: string | undefined): boolean {
  if (!role) return true;
  return (ROLE_RANK[currentRole] ?? 0) >= (ROLE_RANK[role] ?? 0);
}

/* ----------------------------------------------------------------------------- theme ------- */
const THEME_KEY = "mf.theme";
function applyTheme(theme: string): void {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* private mode or blocked storage: the theme simply does not persist. */
  }
}
themeToggle.addEventListener("click", () => {
  applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
});
try {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored) applyTheme(stored);
} catch {
  /* ignore */
}

/* ----------------------------------------------------------------------------- tabs -------- */
function renderTabs(counts: Record<string, number | null> = {}): void {
  clear(tabsRoot);
  for (const pane of PANES) {
    const tab = el("button", {
      class: "tab",
      type: "button",
      role: "tab",
      id: `tab-${pane.id}`,
      "aria-selected": String(pane.id === activePane),
      "aria-controls": "pane-root",
    }, pane.label);
    const count = counts[pane.id];
    if (typeof count === "number" && count > 0) {
      tab.appendChild(el("span", { class: `count ${pane.id === "quarantine" || pane.id === "conflicts" ? "hot" : ""}`, text: String(count) }));
    }
    tab.addEventListener("click", () => void show(pane.id));
    tabsRoot.appendChild(tab);
  }
}

async function refreshCounts(): Promise<void> {
  const counts: Record<string, number | null> = {};
  await Promise.all(PANES.filter((p) => p.count && hasRole(p.needsRole)).map(async (pane) => {
    try {
      counts[pane.id] = await pane.count!();
    } catch {
      counts[pane.id] = null;
    }
  }));
  renderTabs(counts);
}

async function show(paneId: string): Promise<void> {
  const pane = PANES.find((p) => p.id === paneId) ?? PANES[0]!;
  activePane = pane.id;
  window.location.hash = pane.id;
  renderTabs();
  clear(paneRoot);
  try {
    await pane.render(paneRoot, () => void refreshCounts());
  } catch (error) {
    clear(paneRoot);
    paneRoot.appendChild(error instanceof ApiError
      ? errorBox(error.message, `${error.status} ${error.code}`)
      : errorBox(String(error)));
  }
  void refreshCounts();
}

/* ----------------------------------------------------------------------------- identity ---- */
async function loadPrincipals(): Promise<void> {
  try {
    const { items } = await api.principals();
    principals = items;
  } catch {
    principals = [];
  }
  clear(principalSelect);
  if (!principals.length) {
    // The demo-token listing is OFF by default — it only exists for the bundled local demo, and
    // serving credentials from an unauthenticated route was a real finding in the project's own
    // red-team review. Every other deployment lands here, where the operator supplies a token.
    principalField.hidden = true;
    tokenField.hidden = false;
    identityBadge.className = "badge badge-muted";
    identityBadge.textContent = "paste a bearer token";
    identityBadge.title =
      "Tokens are issued by `make setup` and printed into .env. The demo-token listing is " +
      "disabled unless MF_DEV_EXPOSE_DEMO_TOKENS=1.";
    const stored = readStoredToken();
    if (stored) {
      tokenInput.value = stored;
      await useToken(stored);
    }
    return;
  }
  principalField.hidden = false;
  tokenField.hidden = true;
  for (const p of principals) {
    principalSelect.appendChild(el("option", { value: p.id, text: `${p.label} (${p.role})` }));
  }
  const preferred = principals.find((p) => p.role === "reviewer") ?? principals[0]!;
  principalSelect.value = preferred.id;
  await useP(preferred.id);
}

async function useP(principalId: string): Promise<void> {
  const principal = principals.find((p) => p.id === principalId);
  if (!principal) return;
  setToken(principal.token);
  try {
    const who = await api.whoami();
    currentRole = who.role;
    clear(identityBadge);
    identityBadge.className = "badge badge-ok";
    identityBadge.appendChild(document.createTextNode(`${who.principal} · ${who.role} · tenant ${who.tenant_id}`));
    identityBadge.title =
      "Resolved server-side from the bearer token. The dashboard never sends a tenant_id, " +
      "principal or trust_tier field; if it did, the server would strip and audit it.";
  } catch (error) {
    identityBadge.className = "badge badge-bad";
    identityBadge.textContent = `identity: ${error instanceof ApiError ? error.code : "error"}`;
  }
}

const TOKEN_KEY = "mf.token";

function readStoredToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

/** Adopt a manually supplied bearer token.
 *
 *  Kept in `sessionStorage`, not `localStorage`: it is a credential, so it should not outlive the
 *  browser session. Wrapped in try/catch because storage throws in private windows.
 */
async function useToken(token: string): Promise<void> {
  setToken(token);
  try {
    sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage unavailable; the token still applies for this page load */
  }
  try {
    const who = await api.whoami();
    currentRole = who.role;
    clear(identityBadge);
    identityBadge.className = "badge badge-ok";
    identityBadge.appendChild(
      document.createTextNode(`${who.principal} · ${who.role} · tenant ${who.tenant_id}`),
    );
  } catch (error) {
    identityBadge.className = "badge badge-bad";
    identityBadge.textContent =
      error instanceof ApiError && error.status === 401 ? "token rejected" : "identity error";
    return;
  }
  await show(activePane);
}

tokenApply.addEventListener("click", () => void useToken(tokenInput.value.trim()));
tokenInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    void useToken(tokenInput.value.trim());
  }
});

principalSelect.addEventListener("change", async () => {
  await useP(principalSelect.value);
  toast(`Acting as ${principalSelect.value}. The server resolves this from the token, not from any request field.`);
  await show(activePane);
});

/* ----------------------------------------------------------------------------- health ------ */
async function refreshHealth(): Promise<void> {
  try {
    const health = await api.health();
    clear(healthBadge);
    healthBadge.className = `badge badge-${health.status === "ok" ? "ok" : "bad"}`;
    healthBadge.appendChild(document.createTextNode(health.status === "ok" ? "backend ok" : "degraded"));
    healthBadge.title = health.notes.join(" · ") || `FTS5 ${health.fts5 ? "available" : "MISSING"}`;
    clear(footerVersions);
    footerVersions.appendChild(badge(`detector ${health.detector_version}`, "muted"));
    footerVersions.appendChild(badge(`policy ${health.policy_revision}`, "muted"));
    footerVersions.appendChild(badge(`schema ${health.schema_version ?? "?"}`, "muted"));
    footerVersions.appendChild(badge(`FTS5 ${health.fts5 ? "on" : "OFF"}`, health.fts5 ? "ok" : "bad"));
    if (health.unguarded_baseline_enabled) {
      footerVersions.appendChild(badge("labelled baseline endpoint enabled", "warn"));
    }
  } catch {
    healthBadge.className = "badge badge-bad";
    healthBadge.textContent = "backend unreachable";
  }
}

/* ----------------------------------------------------------------------------- boot -------- */
async function boot(): Promise<void> {
  renderTabs();
  await refreshHealth();
  await loadPrincipals();
  const fromHash = window.location.hash.replace("#", "");
  await show(PANES.some((p) => p.id === fromHash) ? fromHash : PANES[0]!.id);
  window.setInterval(() => void refreshHealth(), 15000);
}

window.addEventListener("hashchange", () => {
  const paneId = window.location.hash.replace("#", "");
  if (paneId && paneId !== activePane && PANES.some((p) => p.id === paneId)) void show(paneId);
});

void boot();
