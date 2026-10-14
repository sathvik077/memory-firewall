/** Pane 3 — Quarantine Inbox: the reviewer's workspace, with real evidence and real transitions. */
import { ApiError, api } from "../api.js";
import {
  badge, card, clear, el, empty, errorBox, highlighted, severityBadge, spinner, stateBadge,
  tierBadge, toast,
} from "../dom.js";
import type { QuarantineItem } from "../types.js";

export async function renderQuarantine(root: HTMLElement, onChange: () => void): Promise<void> {
  clear(root);
  root.appendChild(el("div", { class: "pane-head" },
    el("h1", { text: "Quarantine inbox" }),
    el("p", { text:
      "Content withheld from active memory, with the exact span that caused it. Approving or " +
      "rejecting is a transactional state change: the index and the tables move together, the " +
      "actor and reason are recorded, and an illegal transition is refused rather than defaulted." }),
  ));
  const body = el("div", { class: "grid" });
  body.appendChild(spinner("loading queue"));
  root.appendChild(body);

  try {
    const { items } = await api.quarantine();
    clear(body);
    if (!items.length) {
      body.appendChild(empty("Queue is empty",
        "Nothing is withheld right now. Ingest a poisoned sample from the Ingest & Scan pane to populate it."));
      return;
    }
    body.appendChild(el("p", { class: "note", text:
      `${items.length} item(s) withheld. Previews render invisible characters as visible U+XXXX ` +
      "tokens — a reviewer who cannot see the payload cannot review it." }));
    for (const item of items) {
      body.appendChild(renderItem(item, onChange, root));
    }
  } catch (error) {
    clear(body);
    if (error instanceof ApiError && error.status === 403) {
      body.appendChild(empty("Reviewer access required",
        "The review queue contains quarantined text, so it is reviewer-only. Switch \u201cActing " +
        "as\u201d to support-admin to open it."));
      return;
    }
    body.appendChild(error instanceof ApiError
      ? errorBox(error.message, `${error.status} ${error.code}`)
      : errorBox(String(error)));
  }
}

function renderItem(item: QuarantineItem, onChange: () => void, root: HTMLElement): HTMLElement {
  const spans = item.findings.map(
    (f) => [f.evidence_start - item.raw_start, f.evidence_end - item.raw_start] as [number, number],
  );
  const body = el("div");
  body.appendChild(el("div", { class: "row" },
    stateBadge(item.state),
    tierBadge(item.trust_tier),
    severityBadge(item.max_severity),
    badge(`risk ${item.risk_score.toFixed(3)}`, "muted"),
    badge(`${item.source_id}#v${item.version}`, "muted"),
    badge(item.title ?? item.document_id, "muted"),
  ));

  body.appendChild(el("h3", { class: "hint", text: "Content, with the triggering spans highlighted" }));
  body.appendChild(highlighted(item.text, spans));

  if (item.findings.length) {
    const findings = el("div");
    for (const f of item.findings) {
      const node = el("div", { class: "finding" });
      node.appendChild(el("div", { class: "finding-head" },
        badge(f.rule_id, "info"), severityBadge(f.severity), badge(f.rule_family, "muted"),
        badge(`confidence ${f.confidence}`, "muted"),
        f.mitigated_by ? badge(`mitigated: ${f.mitigated_by}`, "ok") : null,
        badge(f.detector_version, "muted"),
      ));
      node.appendChild(el("div", { class: "finding-why", text: f.confidence_semantics }));
      if (f.normalization_applied) {
        node.appendChild(el("div", { class: "finding-why", text: `Normalisation: ${f.normalization_applied}` }));
      }
      findings.appendChild(node);
    }
    body.appendChild(el("h3", { class: "hint", text: "Evidence" }));
    body.appendChild(findings);
  }

  const reason = el("input", { type: "text", placeholder: "reason (required, stored in the audit trail)" });
  const approve = el("button", { class: "btn small", type: "button", text: "Approve" });
  const reject = el("button", { class: "btn small danger", type: "button", text: "Reject" });

  async function decide(decision: "approve" | "reject"): Promise<void> {
    if (!reason.value.trim()) {
      toast("A reason is required — it is stored against the decision.", "bad");
      reason.focus();
      return;
    }
    approve.disabled = reject.disabled = true;
    try {
      await api.review(item.chunk_id, decision, reason.value.trim());
      toast(`Chunk ${decision}d. The index was updated in the same transaction.`, "good");
      onChange();
      await renderQuarantine(root, onChange);
    } catch (error) {
      toast(error instanceof ApiError ? `${error.code}: ${error.message}` : String(error), "bad");
      approve.disabled = reject.disabled = false;
    }
  }
  approve.addEventListener("click", () => void decide("approve"));
  reject.addEventListener("click", () => void decide("reject"));

  body.appendChild(el("div", { class: "row" },
    el("label", { class: "field grow" },
      el("span", { text: "Review decision" }), reason),
    approve, reject));
  body.appendChild(el("p", { class: "note caveat", text:
    "A detected red flag is evidence, not proof of malicious intent. Approving is a documented " +
    "trust transition for this specific content; it does not relabel the source as authoritative." }));

  return card(`Chunk ${item.chunk_id.slice(0, 14)}…`, undefined, body);
}
