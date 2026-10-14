/** Pane 5 — Retrieval Trace: the pre-retrieval guard, including what it refused. */
import { ApiError, api } from "../api.js";
import {
  badge, card, clear, el, empty, errorBox, fmtMs, fmtTime, highlighted, spinner, table, td,
  tierBadge,
} from "../dom.js";
import type { ContextPack, RetrievalResult } from "../types.js";

export async function renderTrace(root: HTMLElement): Promise<void> {
  clear(root);
  root.appendChild(el("div", { class: "pane-head" },
    el("h1", { text: "Retrieval trace" }),
    el("p", { text:
      "Enforcement point 2. Tenant, per-principal ACL, chunk and version state, both time " +
      "coordinates and the integrity manifest are all predicates inside the single SQL statement " +
      "that performs the search, so an ineligible chunk cannot be ranked, counted, cited or " +
      "returned. The exclusion trace is admin-only by design." }),
  ));

  const form = el("form", { class: "card" });
  form.appendChild(el("h2", { text: "Run a guarded query" }));
  const query = el("input", { type: "text", value: "What is the refund period?", required: "required" });
  const asOfValid = el("input", { type: "datetime-local" });
  const asOfRecorded = el("input", { type: "datetime-local" });
  const traceBox = el("input", { type: "checkbox", id: "want-trace" });
  traceBox.checked = true;
  const submit = el("button", { class: "btn", type: "submit", text: "Retrieve" });
  form.appendChild(el("div", { class: "grid two" },
    el("label", { class: "field" }, el("span", { text: "Query" }), query),
    el("label", { class: "field" }, el("span", { text: "As of valid time (what was in force)" }), asOfValid),
    el("label", { class: "field" }, el("span", { text: "As of recorded time (what we believed)" }), asOfRecorded),
  ));
  form.appendChild(el("div", { class: "row" }, submit,
    el("label", { class: "field compact" }, traceBox, el("span", { text: "request exclusion trace (admin only)" }))));
  root.appendChild(form);

  const out = el("div", { class: "grid" });
  root.appendChild(out);

  async function run(): Promise<void> {
    submit.disabled = true;
    clear(out);
    out.appendChild(spinner("querying"));
    try {
      const body: Record<string, unknown> = { query: query.value, limit: 5, include_trace: traceBox.checked };
      if (asOfValid.value) body["as_of_valid"] = `${asOfValid.value}:00Z`;
      if (asOfRecorded.value) body["as_of_recorded"] = `${asOfRecorded.value}:00Z`;
      const [result, pack] = await Promise.all([
        api.retrieve(body as never),
        api.contextPack({ query: query.value, limit: 5 }),
      ]);
      clear(out);
      out.appendChild(renderResult(result));
      out.appendChild(renderPack(pack));
      out.appendChild(await renderExposures());
    } catch (error) {
      clear(out);
      out.appendChild(error instanceof ApiError ? errorBox(error.message, `${error.status} ${error.code}`) : errorBox(String(error)));
    } finally {
      submit.disabled = false;
    }
  }
  form.addEventListener("submit", (event) => { event.preventDefault(); void run(); });
  await run();
}

function renderResult(result: RetrievalResult): HTMLElement {
  const body = el("div");
  body.appendChild(el("div", { class: "row" },
    badge(result.guard_enforced ? "guard enforced" : "GUARD OFF", result.guard_enforced ? "ok" : "bad"),
    result.fail_closed ? badge("failed closed — nothing returned", "bad") : null,
    badge(`identity: ${result.identity_source}`, "ok"),
    badge(`tenant ${result.tenant_id}`, "muted"),
    badge(`${result.filtered_count} returned / ${result.candidate_count} eligible`, "muted"),
    badge(fmtMs(result.latency_ms), "muted"),
    badge(`run ${result.run_id.slice(0, 12)}…`, "muted"),
  ));
  body.appendChild(el("p", { class: "note", text:
    `Valid time ${fmtTime(result.as_of_valid)} · recorded time ${fmtTime(result.as_of_recorded)}` }));
  if (result.fail_reason) body.appendChild(el("p", { class: "note caveat", text: result.fail_reason }));
  for (const note of result.notes ?? []) {
    body.appendChild(el("p", { class: "note caveat", text: note }));
  }

  if (result.context_chunks.length === 0) {
    body.appendChild(empty("No eligible evidence",
      "The guard returned nothing, so a downstream caller must decline rather than answer."));
  } else {
    for (const chunk of result.context_chunks) {
      const node = el("div");
      node.appendChild(el("div", { class: "row" },
        badge(chunk.citation, "ok"), tierBadge(chunk.trust_tier),
        badge(`score ${chunk.score.toFixed(4)}`, "muted"),
        ...chunk.risk_tags.map((t) => badge(t, t.includes("mitigated") ? "ok" : "warn")),
      ));
      node.appendChild(highlighted(chunk.text, []));
      body.appendChild(node);
    }
  }

  if (result.integrity_alerts.length) {
    const alerts = el("div");
    for (const a of result.integrity_alerts) {
      alerts.appendChild(el("div", { class: "finding" },
        el("div", { class: "finding-head" }, badge(String(a["reason"]), "bad"),
          badge(String(a["chunk_id"]).slice(0, 14), "muted")),
        el("div", { class: "finding-why", text: String(a["detail"] ?? "") })));
    }
    body.appendChild(el("h3", { class: "hint", text: "Integrity alerts" }));
    body.appendChild(alerts);
  }

  if (result.trace && result.trace.length) {
    body.appendChild(el("h3", { class: "hint", text: "Excluded candidates (admin-only trace)" }));
    body.appendChild(table(["chunk", "source", "chunk state", "version state", "tier", "reasons"],
      result.trace.map((e) => [
        td(el("span", { class: "mono", text: e.chunk_id.slice(0, 14) })),
        td(el("span", { class: "mono", text: e.source_id })),
        e.chunk_state ?? "—", e.version_state ?? "—",
        e.trust_tier ? tierBadge(e.trust_tier) : "—",
        td(el("span", { class: "mono", text: e.reasons.join(", ") })),
      ])));
    body.appendChild(el("p", { class: "note caveat", text:
      "A reader never receives this list, nor any count derived from it. It exists so an operator " +
      "can prove why something was withheld." }));
  } else if (result.trace) {
    body.appendChild(el("p", { class: "note", text: "No candidates were excluded for this query." }));
  }
  return card("Guarded result", undefined, body);
}

function renderPack(pack: ContextPack): HTMLElement {
  const body = el("div");
  body.appendChild(el("div", { class: "row" },
    badge(pack.policy_decision, pack.insufficient_evidence ? "bad" : "ok"),
    badge(`${pack.chunks.length} chunk(s)`, "muted"),
    ...pack.citations.map((c) => badge(c, "ok")),
  ));
  body.appendChild(el("h3", { class: "hint", text: "Deterministic answer (no model call)" }));
  body.appendChild(pack.answer
    ? el("div", { class: "evidence", text: pack.answer })
    : empty("No answer produced",
        "Either no eligible evidence exists, or the evidence contains no claim of the governed typed domain."));
  for (const note of pack.notes) body.appendChild(el("p", { class: "note", text: note }));
  return card("Context pack handed downstream", "Only eligible chunks, each carrying its provenance.", body);
}

async function renderExposures(): Promise<HTMLElement> {
  try {
    const { items } = await api.exposures();
    const rows = items.slice(0, 12).map((e) => [
      td(el("span", { class: "mono", text: e.run_id.slice(0, 12) })),
      td(el("span", { class: "mono", text: e.principal_id })),
      e.query.slice(0, 48),
      td(String(e.candidate_count), "num"),
      td(String(e.returned_chunk_ids.length), "num"),
      e.fail_closed ? badge("fail-closed", "bad") : badge("ok", "ok"),
      td(fmtMs(e.latency_ms), "num"),
      fmtTime(e.created_at),
    ]);
    return card("Exposure log", "Every guarded retrieval writes one row, including fail-closed ones.",
      rows.length ? table(["run", "principal", "query", "eligible", "returned", "guard", "latency", "when"], rows)
                  : empty("No retrievals logged yet", "Run a query above."));
  } catch (error) {
    return card("Exposure log", undefined, errorBox(error instanceof ApiError ? error.message : String(error)));
  }
}
