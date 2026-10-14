/** Pane 6 — Memory Ledger: every version and its bitemporal validity history. */
import { ApiError, api } from "../api.js";
import {
  badge, card, clear, el, empty, errorBox, fmtTime, spinner, stateBadge, table, td, tierBadge,
} from "../dom.js";
import type { LedgerRow } from "../types.js";

export async function renderLedger(root: HTMLElement): Promise<void> {
  clear(root);
  root.appendChild(el("div", { class: "pane-head" },
    el("h1", { text: "Memory ledger" }),
    el("p", { text:
      "Every document version with its full validity history. Rows are append-only: a state change " +
      "closes the previous row in system time and inserts a new one, so the ledger can answer both " +
      "“what was in force” and “what did we believe” for any past instant." }),
  ));
  const body = el("div", { class: "grid" });
  body.appendChild(spinner("loading ledger"));
  root.appendChild(body);

  try {
    const { items } = await api.ledger();
    clear(body);
    if (!items.length) {
      body.appendChild(empty("Ledger is empty", "Ingest a document to create the first version."));
      return;
    }
    const byDocument = new Map<string, LedgerRow[]>();
    for (const row of items) {
      const list = byDocument.get(row.document_id) ?? [];
      list.push(row);
      byDocument.set(row.document_id, list);
    }
    for (const [documentId, versions] of byDocument) {
      versions.sort((a, b) => a.version - b.version);
      const first = versions[0]!;
      const inner = el("div");
      inner.appendChild(el("div", { class: "row" },
        tierBadge(first.trust_tier),
        badge(first.source_id, "muted"),
        first.document_status === "active" ? badge("active", "ok") : badge(first.document_status, "bad"),
        first.source_status === "active" ? null : badge(`source ${first.source_status}`, "bad"),
        badge(`${versions.length} version(s)`, "muted"),
      ));

      const timeline = el("div", { class: "timeline" });
      for (const version of versions) {
        const open = version.validity.find((v) => v.system_recorded_to === null);
        const dotClass = open?.state === "active" ? "active"
          : open?.state === "review_required" ? "review"
          : open ? "blocked" : "";
        const item = el("div", { class: "timeline-item" },
          el("div", { class: `timeline-dot ${dotClass}` }));
        const detail = el("div");
        detail.appendChild(el("div", { class: "row tight" },
          el("strong", { text: `v${version.version}` }),
          open ? stateBadge(open.state) : badge("no open row", "bad"),
          badge(`sha256 ${version.content_sha256.slice(0, 12)}…`, "muted"),
          badge(fmtTime(version.created_at), "muted"),
          ...Object.entries(version.chunk_states).map(([state, n]) => badge(`${n} ${state}`, state === "active" ? "ok" : "warn")),
        ));
        detail.appendChild(table(
          ["state", "effective from", "effective to", "recorded from", "recorded to", "reason"],
          version.validity.map((v) => [
            stateBadge(v.state),
            td(el("span", { class: "mono", text: fmtTime(v.effective_from) })),
            td(el("span", { class: "mono", text: v.effective_to ? fmtTime(v.effective_to) : "open" })),
            td(el("span", { class: "mono", text: fmtTime(v.system_recorded_from) })),
            td(el("span", { class: "mono", text: v.system_recorded_to ? fmtTime(v.system_recorded_to) : "open (current belief)" })),
            v.reason ?? "—",
          ])));
        item.appendChild(detail);
        timeline.appendChild(item);
      }
      inner.appendChild(timeline);
      body.appendChild(card(first.title ?? documentId, `document ${documentId}`, inner));
    }
  } catch (error) {
    clear(body);
    body.appendChild(error instanceof ApiError ? errorBox(error.message, String(error.status)) : errorBox(String(error)));
  }
}
