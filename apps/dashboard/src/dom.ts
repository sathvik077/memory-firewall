/** DOM helpers.
 *
 *  **Security rule for this whole module: no function here ever assigns `innerHTML`.** Untrusted
 *  chunk text is attacker-controlled by definition and a reviewer has to look at it, so every
 *  string becomes a text node. The server also returns a pre-escaped `preview_html`, which this
 *  dashboard deliberately does *not* use — highlights are rebuilt client-side from the finding
 *  offsets with real `<mark>` elements, so no HTML string from the server is ever injected either.
 *  Two independent layers; either alone would be sufficient.
 */

type Attrs = Record<string, string | number | boolean | undefined>;
type Child = Node | string | number | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key === "class") node.className = String(value);
    else if (key === "text") node.textContent = String(value);
    else if (key === "value" && node instanceof HTMLInputElement) node.value = String(value);
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

export function append(parent: Node, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function clear(node: Node): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function badge(text: string, kind: "ok" | "warn" | "bad" | "info" | "muted" = "muted"): HTMLElement {
  return el("span", { class: `badge badge-${kind}`, text });
}

export function stateBadge(state: string): HTMLElement {
  const kind =
    state === "active" ? "ok" : state === "review_required" ? "warn" : state === "superseded" ? "muted" : "bad";
  return badge(state, kind);
}

export function tierBadge(tier: string): HTMLElement {
  const node = badge(tier, tier.startsWith("authoritative") ? "ok" : tier === "reviewed_internal" ? "info" : tier === "unreviewed_internal" ? "warn" : "bad");
  node.classList.add("tier", `tier-${tier}`);
  return node;
}

export function severityBadge(severity: string): HTMLElement {
  const kind =
    severity === "critical" || severity === "high" ? "bad" : severity === "medium" ? "warn" : severity === "none" ? "muted" : "info";
  return badge(severity, kind);
}

export function card(title: string, hint?: string, ...children: Child[]): HTMLElement {
  const node = el("section", { class: "card" }, el("h2", { text: title }));
  if (hint) node.appendChild(el("p", { class: "hint", text: hint }));
  append(node, children);
  return node;
}

export function empty(title: string, detail: string): HTMLElement {
  return el("div", { class: "empty" }, el("strong", { text: title }), el("span", { text: detail }));
}

export function errorBox(message: string, code?: string): HTMLElement {
  const node = el("div", { class: "error" }, el("strong", { text: "Request failed. " }), message);
  if (code) node.appendChild(el("div", {}, el("code", { text: code })));
  return node;
}

export function table(headers: string[], rows: Child[][]): HTMLElement {
  const thead = el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", { text: h }))));
  const tbody = el("tbody");
  for (const row of rows) {
    tbody.appendChild(el("tr", {}, ...row.map((cell) => (cell instanceof HTMLTableCellElement ? cell : el("td", {}, cell)))));
  }
  return el("div", { class: "table-wrap" }, el("table", {}, thead, tbody));
}

export function td(content: Child, cls = ""): HTMLTableCellElement {
  const cell = document.createElement("td");
  if (cls) cell.className = cls;
  append(cell, [content]);
  return cell;
}

/** Render text with `<mark>` over the given half-open spans, using only text nodes. */
export function highlighted(text: string, spans: Array<[number, number]>): HTMLElement {
  const wrap = el("div", { class: "evidence" });
  const bounded = spans
    .map(([s, e]) => [Math.max(0, Math.min(s, text.length)), Math.max(0, Math.min(e, text.length))] as [number, number])
    .filter(([s, e]) => e > s)
    .sort((a, b) => a[0] - b[0]);

  const merged: Array<[number, number]> = [];
  for (const [start, end] of bounded) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1]) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }

  let cursor = 0;
  for (const [start, end] of merged) {
    if (start > cursor) wrap.appendChild(document.createTextNode(visible(text.slice(cursor, start))));
    wrap.appendChild(el("mark", { class: "mf-evidence", text: visible(text.slice(start, end)) }));
    cursor = end;
  }
  wrap.appendChild(document.createTextNode(visible(text.slice(cursor))));
  return wrap;
}

/** Make invisible characters visible: a reviewer who cannot see the payload cannot review it. */
export function visible(text: string): string {
  return text.replace(/[​-‏‪-‮⁠-⁤­﻿؜]/g, (ch) =>
    `␉U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}␊`,
  );
}

export function toast(message: string, kind: "good" | "bad" | "" = ""): void {
  const node = document.getElementById("toast");
  if (!node) return;
  node.className = `toast ${kind}`.trim();
  node.textContent = message;
  node.hidden = false;
  window.clearTimeout((node as HTMLElement & { _t?: number })._t);
  (node as HTMLElement & { _t?: number })._t = window.setTimeout(() => {
    node.hidden = true;
  }, 5200);
}

export function spinner(label = "loading"): HTMLElement {
  return el("div", { class: "note" }, el("span", { class: "spin", text: "◴" }), ` ${label}…`);
}

export function fmtMs(ms: number): string {
  return `${ms.toFixed(1)} ms`;
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.replace("T", " ").replace(/\.\d+Z?$/, "").replace("Z", "");
}

export function shortId(id: string, keep = 10): string {
  return id.length <= keep + 4 ? id : `${id.slice(0, keep)}…`;
}
