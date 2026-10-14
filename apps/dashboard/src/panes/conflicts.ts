/** Pane 4 — Claim Conflict Browser: two evidence-backed claims that cannot both stand. */
import { ApiError, api } from "../api.js";
import { badge, card, clear, el, empty, errorBox, spinner, table, td, tierBadge, toast } from "../dom.js";

export async function renderConflicts(root: HTMLElement, onChange: () => void): Promise<void> {
  clear(root);
  root.appendChild(el("div", { class: "pane-head" },
    el("h1", { text: "Claim conflicts" }),
    el("p", { text:
      "Only claims with the same subject, attribute, region and customer tier are ever compared, " +
      "and only within one narrow governed domain (refund window). A conflict is a review state, " +
      "not a verdict about which document is factually correct." }),
  ));
  const body = el("div", { class: "grid" });
  body.appendChild(spinner("loading conflicts"));
  root.appendChild(body);

  try {
    const { items, note } = await api.conflicts();
    clear(body);
    if (!items.length) {
      body.appendChild(empty("No conflicts", "No two standing claims on the same key disagree."));
      return;
    }
    body.appendChild(el("p", { class: "note", text: note }));

    for (const c of items) {
      const unauthorized = c.incoming_authority !== c.existing_authority;
      const inner = el("div");
      inner.appendChild(el("div", { class: "row" },
        badge(c.kind, "warn"),
        badge(c.status, c.status === "needs_review" ? "warn" : "muted"),
        badge(`${c.region} / ${c.customer_tier}`, "muted"),
      ));
      inner.appendChild(table(["side", "value (days)", "source", "authority"], [
        ["incoming", td(String(c.incoming_value ?? "—"), "num"),
          td(el("span", { class: "mono", text: c.incoming_source })), tierBadge(c.incoming_authority)],
        ["standing", td(String(c.existing_value ?? "—"), "num"),
          td(el("span", { class: "mono", text: c.existing_source })), tierBadge(c.existing_authority)],
      ]));
      if (c.reason) inner.appendChild(el("p", { class: "note", text: c.reason }));
      inner.appendChild(el("p", { class: "note caveat", text: unauthorized
        ? "The incoming claim comes from a source of different authority than the standing value. " +
          "Memory Firewall cannot know which is factually correct; it knows which one came from an " +
          "authority and which did not."
        : "Equal authority on both sides. This is an ordinary review item, not an attack signal." }));

      if (c.status === "needs_review") {
        const reason = el("input", { type: "text", placeholder: "resolution reason" });
        const mkBtn = (label: string, resolution: string, cls: string) => {
          const b = el("button", { class: `btn small ${cls}`, type: "button", text: label });
          b.addEventListener("click", async () => {
            if (!reason.value.trim()) { toast("A resolution reason is required.", "bad"); return; }
            b.disabled = true;
            try {
              await api.resolveConflict(c.id, resolution, reason.value.trim());
              toast("Conflict resolved and recorded.", "good");
              onChange();
              await renderConflicts(root, onChange);
            } catch (error) {
              toast(error instanceof ApiError ? error.message : String(error), "bad");
              b.disabled = false;
            }
          });
          return b;
        };
        inner.appendChild(el("div", { class: "row" },
          el("label", { class: "field grow" }, el("span", { text: "Resolve" }), reason),
          mkBtn("Supersede", "resolved_supersede", "ghost"),
          mkBtn("Dismiss", "resolved_dismissed", "ghost"),
          mkBtn("Reject incoming", "resolved_rejected", "danger"),
        ));
      }
      body.appendChild(card(`Conflict ${c.id.slice(0, 14)}…`, undefined, inner));
    }
  } catch (error) {
    clear(body);
    body.appendChild(error instanceof ApiError ? errorBox(error.message, String(error.status)) : errorBox(String(error)));
  }
}
