/** Pane 8 — Attack Lab: the scenarios the test suite runs, on demand, against real databases. */
import { ApiError, api } from "../api.js";
import {
  badge, card, clear, el, empty, errorBox, highlighted, spinner, table, td, toast,
} from "../dom.js";
import type { ScenarioMeta, ScenarioResult, UnguardedComparison } from "../types.js";

export async function renderAttackLab(root: HTMLElement): Promise<void> {
  clear(root);
  root.appendChild(el("div", { class: "pane-head" },
    el("h1", { text: "Attack lab" }),
    el("p", { text:
      "Each scenario builds its own disposable database, runs real ingestion and real retrieval, " +
      "and reports the observed outcome beside the expectation. These are the same functions the " +
      "test suite asserts, so a green lab and a green suite cannot disagree. Nothing here is a " +
      "pre-seeded alert." }),
  ));

  const body = el("div", { class: "grid" });
  body.appendChild(spinner("loading scenarios"));
  root.appendChild(body);

  try {
    const { items, note } = await api.scenarios();
    clear(body);
    body.appendChild(el("p", { class: "note", text: note }));

    const runAll = el("button", { class: "btn", type: "button", text: "Run all scenarios" });
    const summary = el("div", { class: "row" });
    body.appendChild(el("div", { class: "card" },
      el("h2", { text: "Run" }), el("div", { class: "row" }, runAll, summary)));

    const results = el("div", { class: "grid" });
    body.appendChild(results);

    const cards = new Map<string, HTMLElement>();
    for (const meta of items) {
      const node = renderScenarioCard(meta, results, cards);
      cards.set(meta.id, node);
      results.appendChild(node);
    }

    runAll.addEventListener("click", async () => {
      runAll.disabled = true;
      clear(summary);
      summary.appendChild(el("span", { class: "spin", text: "◴" }));
      let passed = 0;
      let failed = 0;
      for (const meta of items) {
        try {
          const result = await api.runScenario(meta.id);
          const replacement = renderScenarioCard(meta, results, cards, result);
          cards.get(meta.id)?.replaceWith(replacement);
          cards.set(meta.id, replacement);
          result.passed ? passed++ : failed++;
        } catch {
          failed++;
        }
      }
      clear(summary);
      summary.appendChild(badge(`${passed} passed`, "ok"));
      if (failed) summary.appendChild(badge(`${failed} failed`, "bad"));
      runAll.disabled = false;
      toast(`${passed}/${passed + failed} scenarios passed.`, failed ? "bad" : "good");
    });

    body.appendChild(await renderComparison());
  } catch (error) {
    clear(body);
    body.appendChild(error instanceof ApiError ? errorBox(error.message, String(error.status)) : errorBox(String(error)));
  }
}

function renderScenarioCard(
  meta: ScenarioMeta,
  container: HTMLElement,
  cards: Map<string, HTMLElement>,
  result?: ScenarioResult,
): HTMLElement {
  const body = el("div");
  body.appendChild(el("div", { class: "row tight" },
    badge(meta.kind, meta.kind === "attack" ? "bad" : meta.kind === "benign" ? "ok" : "info"),
    badge(meta.contract_ref, "muted"),
    result ? badge(result.passed ? "PASS" : "FAIL", result.passed ? "ok" : "bad") : badge("not run", "muted"),
  ));
  body.appendChild(el("p", { class: "hint", text: meta.description }));
  body.appendChild(el("p", { class: "note", text: `Expected: ${meta.expectation}` }));

  const run = el("button", { class: "btn small ghost", type: "button", text: result ? "Re-run" : "Run" });
  run.addEventListener("click", async () => {
    run.disabled = true;
    try {
      const fresh = await api.runScenario(meta.id);
      const replacement = renderScenarioCard(meta, container, cards, fresh);
      cards.get(meta.id)?.replaceWith(replacement);
      cards.set(meta.id, replacement);
    } catch (error) {
      toast(error instanceof ApiError ? error.message : String(error), "bad");
      run.disabled = false;
    }
  });
  body.appendChild(el("div", { class: "row" }, run));

  if (result) {
    if (result.steps.length) {
      const list = el("ol", { class: "reasons" });
      result.steps.forEach((s) => list.appendChild(el("li", { text: s })));
      body.appendChild(el("h3", { class: "hint", text: "Steps actually executed" }));
      body.appendChild(list);
    }
    body.appendChild(el("h3", { class: "hint", text: "Assertions" }));
    body.appendChild(table(["check", "expected", "observed", ""],
      result.checks.map((c) => [
        c.name,
        td(el("span", { class: "mono", text: truncate(c.expected) })),
        td(el("span", { class: "mono", text: truncate(c.observed) })),
        c.passed ? badge("pass", "ok") : badge("FAIL", "bad"),
      ])));
    if (result.caveat) body.appendChild(el("p", { class: "note caveat", text: result.caveat }));
  }
  return card(meta.name, undefined, body);
}

function truncate(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (text === undefined) return "—";
  return text.length > 70 ? `${text.slice(0, 70)}…` : text;
}

async function renderComparison(): Promise<HTMLElement> {
  const body = el("div");
  const query = el("input", { type: "text", value: "What is the refund period?" });
  const button = el("button", { class: "btn", type: "button", text: "Compare" });
  const out = el("div");
  body.appendChild(el("div", { class: "row" },
    el("label", { class: "field grow" }, el("span", { text: "Query" }), query), button));
  body.appendChild(out);

  button.addEventListener("click", async () => {
    button.disabled = true;
    clear(out);
    out.appendChild(spinner("comparing"));
    try {
      const result = await api.unguardedComparison(query.value);
      clear(out);
      out.appendChild(renderComparisonResult(result));
    } catch (error) {
      clear(out);
      out.appendChild(error instanceof ApiError
        ? errorBox(`${error.message}`, `${error.status} ${error.code}`)
        : errorBox(String(error)));
      if (error instanceof ApiError && error.code === "forbidden") {
        out.appendChild(el("p", { class: "note", text:
          "The labelled baseline endpoint is disabled unless MF_ENABLE_UNGUARDED_BASELINE=1 and " +
          "the caller holds an admin token. `make setup` enables it for the local demo profile." }));
      }
    } finally {
      button.disabled = false;
    }
  });

  body.appendChild(el("p", { class: "note", text:
    "Requires an admin token (switch \u201cActing as\u201d to support-root) and " +
    "MF_ENABLE_UNGUARDED_BASELINE=1, which `make setup` turns on for the local demo." }));
  return card("Unguarded vs guarded, same corpus",
    "A real side-by-side over the same stored chunks. The left column represents a pipeline with " +
    "no write-time firewall, so it searches everything that was ever stored — including what this " +
    "system quarantined. It is a measurement baseline, not product output.", body);
}

function renderComparisonResult(result: UnguardedComparison): HTMLElement {
  const split = el("div", { class: "split" });

  const left = el("div", { class: "compare-col unguarded" },
    el("h3", { text: "Naive unguarded retrieval (synthetic baseline)" }),
    el("p", { class: "note caveat", text: result.unguarded_baseline.warning }));
  if (!result.unguarded_baseline.hits.length) {
    left.appendChild(empty("No hits", "Nothing matched."));
  } else {
    for (const hit of result.unguarded_baseline.hits) {
      left.appendChild(el("div", { class: "row tight" },
        badge(hit.source_id, "muted"),
        badge(hit.chunk_state, hit.chunk_state === "active" ? "ok" : "bad")));
      left.appendChild(highlighted(hit.raw_text, []));
    }
  }

  const right = el("div", { class: "compare-col guarded" },
    el("h3", { text: "Memory Firewall (actual system output)" }));
  if (!result.guarded_result.context_chunks.length) {
    right.appendChild(empty("No eligible evidence", "The guard returned nothing."));
  } else {
    for (const chunk of result.guarded_result.context_chunks) {
      right.appendChild(el("div", { class: "row tight" }, badge(chunk.citation, "ok")));
      right.appendChild(highlighted(chunk.text, []));
    }
  }

  split.appendChild(left);
  split.appendChild(right);

  const wrap = el("div");
  wrap.appendChild(el("div", { class: "row" },
    badge(`${result.comparison.unguarded_hit_count} unguarded hits`, "bad"),
    badge(`${result.comparison.guarded_hit_count} guarded hits`, "ok"),
    badge(`${result.comparison.chunks_withheld_by_guard.length} withheld by the guard`, "warn"),
  ));
  wrap.appendChild(split);
  return wrap;
}
