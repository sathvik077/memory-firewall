/** Pane 2 — Source Trust Map: where trust actually comes from. */
import { ApiError, api } from "../api.js";
import { badge, card, clear, el, errorBox, spinner, table, td, tierBadge, toast } from "../dom.js";
import type { SourceRow, Stats } from "../types.js";

const TIER_ORDER = [
  "authoritative_signed", "authoritative_reviewed", "reviewed_internal",
  "unreviewed_internal", "external_untrusted",
];

export async function renderSources(root: HTMLElement, onChange: () => void): Promise<void> {
  clear(root);
  root.appendChild(el("div", { class: "pane-head" },
    el("h1", { text: "Source trust map" }),
    el("p", { text:
      "Trust tier is administrative state set by an admin and stored server-side. No document can " +
      "raise its own tier by claiming to be signed, approved or authoritative — the ingest path " +
      "never passes a caller-supplied tier at all." }),
  ));
  const body = el("div", { class: "grid" });
  body.appendChild(spinner("loading sources"));
  root.appendChild(body);

  try {
    const [{ sources }, stats] = await Promise.all([api.sources(), api.stats()]);
    clear(body);
    body.appendChild(renderStats(stats));

    const byTier = new Map<string, SourceRow[]>();
    for (const s of sources) {
      const list = byTier.get(s.trust_tier) ?? [];
      list.push(s);
      byTier.set(s.trust_tier, list);
    }

    const ladder = el("div", { class: "grid" });
    for (const tier of TIER_ORDER) {
      const rows = byTier.get(tier) ?? [];
      if (!rows.length) continue;
      const heading = el("div", { class: "row tight" },
        el("strong", { text: tier.replace(/_/g, " ") }),
        tierBadge(tier),
        badge(`${rows.length} source(s)`, "muted"));
      ladder.appendChild(card(tier.replace(/_/g, " "),
        tier.startsWith("authoritative")
          ? "Reviewer-backed authority. Claims from here supersede weaker sources."
          : tier === "external_untrusted"
            ? "Attacker-reachable. Content here is data, never instructions."
            : undefined,
        heading,
        table(["source", "trust tier", "connector", "owner", "status", "docs", "read ACL"],
          rows.map((s) => [
            td(el("span", { class: "mono", text: s.id })),
            tierBadge(s.trust_tier),
            s.connector_type,
            s.owner ?? "—",
            s.status === "active" ? badge("active", "ok") : badge(`revoked: ${s.revoked_reason ?? ""}`, "bad"),
            td(String(s.documents), "num"),
            td(el("span", { class: "mono", text: s.read_acl.join(", ") || "—" })),
          ])),
      ));
    }
    body.appendChild(ladder);

    const revokeForm = el("form", { class: "card" });
    revokeForm.appendChild(el("h2", { text: "Revoke a source" }));
    revokeForm.appendChild(el("p", { class: "hint", text:
      "Takes effect on the very next query. There is no cross-request cache in this build, so " +
      "there is nothing to invalidate and no stale-read window." }));
    const select = el("select", { required: "required" });
    sources.filter((s) => s.status === "active")
      .forEach((s) => select.appendChild(el("option", { value: s.id, text: s.id })));
    const reason = el("input", { type: "text", required: "required", placeholder: "reason (stored in the audit trail)" });
    const button = el("button", { class: "btn danger", type: "submit", text: "Revoke" });
    revokeForm.appendChild(el("div", { class: "grid two" },
      el("label", { class: "field" }, el("span", { text: "Source" }), select),
      el("label", { class: "field" }, el("span", { text: "Reason" }), reason)));
    revokeForm.appendChild(el("div", { class: "row" }, button));
    revokeForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      button.disabled = true;
      try {
        await api.revokeSource(select.value, reason.value);
        toast(`Revoked ${select.value}. Retrieval excludes it from the next query onward.`, "good");
        onChange();
        await renderSources(root, onChange);
      } catch (error) {
        toast(error instanceof ApiError ? error.message : String(error), "bad");
      } finally {
        button.disabled = false;
      }
    });
    body.appendChild(revokeForm);
  } catch (error) {
    clear(body);
    body.appendChild(error instanceof ApiError
      ? errorBox(error.message, `${error.status} ${error.code}`)
      : errorBox(String(error)));
  }
}

function renderStats(stats: Stats): HTMLElement {
  const wrap = el("div", { class: "grid stats" });
  const items: Array<[string, string | number, string]> = [
    ["sources", stats.sources, ""],
    ["documents", stats.documents, ""],
    ["active chunks", stats.active_chunks, "good"],
    ["withheld chunks", stats.withheld_chunks, stats.withheld_chunks ? "warn" : ""],
    ["open conflicts", stats.open_conflicts, stats.open_conflicts ? "warn" : ""],
    ["retrievals logged", stats.retrievals, ""],
    ["manifest entries", stats.manifest_entries, ""],
  ];
  for (const [label, value, kind] of items) {
    wrap.appendChild(el("div", { class: `card stat ${kind}` },
      el("span", { class: "value", text: String(value) }),
      el("span", { class: "label", text: label })));
  }
  return wrap;
}
