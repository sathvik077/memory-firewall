/** Pane 7 — Memory Time Machine: replay what was visible, and what we believed. */
import { ApiError, api } from "../api.js";
import {
  badge, card, clear, el, empty, errorBox, fmtTime, highlighted, spinner, table, td, toast,
} from "../dom.js";
import type { ReplayResult } from "../types.js";

export async function renderTimeMachine(root: HTMLElement, onChange: () => void): Promise<void> {
  clear(root);
  root.appendChild(el("div", { class: "pane-head" },
    el("h1", { text: "Memory time machine" }),
    el("p", { text:
      "A snapshot pins two coordinates: a valid time (which policy was in force) and a recorded " +
      "time (what the system knew). Replaying holds the valid time fixed and moves only the " +
      "recorded time, which is the only comparison that shows what the system has since learned " +
      "about that same moment — and names the revision that changed the answer." }),
  ));

  const body = el("div", { class: "grid" });
  body.appendChild(spinner("loading snapshots"));
  root.appendChild(body);

  try {
    const { items } = await api.snapshots();
    clear(body);

    const createForm = el("form", { class: "card" });
    createForm.appendChild(el("h2", { text: "Take a snapshot" }));
    createForm.appendChild(el("p", { class: "hint", text:
      "Pin a valid time in the future to ask “what would we have said about then, as known now?”" }));
    const label = el("input", { type: "text", required: "required", placeholder: "label" });
    const asOfValid = el("input", { type: "datetime-local" });
    const note = el("input", { type: "text", placeholder: "note (optional)" });
    const createBtn = el("button", { class: "btn", type: "submit", text: "Create snapshot" });
    createForm.appendChild(el("div", { class: "grid three" },
      el("label", { class: "field" }, el("span", { text: "Label" }), label),
      el("label", { class: "field" }, el("span", { text: "As of valid time" }), asOfValid),
      el("label", { class: "field" }, el("span", { text: "Note" }), note)));
    createForm.appendChild(el("div", { class: "row" }, createBtn));
    createForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      createBtn.disabled = true;
      try {
        const payload: Record<string, unknown> = { label: label.value, note: note.value };
        if (asOfValid.value) payload["as_of_valid"] = `${asOfValid.value}:00Z`;
        await api.createSnapshot(payload as never);
        toast("Snapshot created.", "good");
        onChange();
        await renderTimeMachine(root, onChange);
      } catch (error) {
        toast(error instanceof ApiError ? error.message : String(error), "bad");
        createBtn.disabled = false;
      }
    });
    body.appendChild(createForm);

    if (!items.length) {
      body.appendChild(empty("No snapshots yet", "Create one above, or run `make seed`."));
      return;
    }

    const replayForm = el("form", { class: "card" });
    replayForm.appendChild(el("h2", { text: "Replay" }));
    const select = el("select", { required: "required" });
    for (const s of items) {
      select.appendChild(el("option", { value: s.id,
        text: `${s.label} — valid ${fmtTime(s.as_of_valid)}, recorded ${fmtTime(s.as_of_recorded)}` }));
    }
    const query = el("input", { type: "text", value: "refund period", required: "required" });
    const replayBtn = el("button", { class: "btn", type: "submit", text: "Replay query" });
    replayForm.appendChild(el("div", { class: "grid two" },
      el("label", { class: "field" }, el("span", { text: "Snapshot" }), select),
      el("label", { class: "field" }, el("span", { text: "Query" }), query)));
    replayForm.appendChild(el("div", { class: "row" }, replayBtn));
    body.appendChild(replayForm);

    const out = el("div", { class: "grid" });
    body.appendChild(out);

    async function replay(): Promise<void> {
      replayBtn.disabled = true;
      clear(out);
      out.appendChild(spinner("replaying"));
      try {
        const result = await api.replay(select.value, query.value);
        clear(out);
        out.appendChild(renderReplay(result));
      } catch (error) {
        clear(out);
        out.appendChild(error instanceof ApiError ? errorBox(error.message, String(error.status)) : errorBox(String(error)));
      } finally {
        replayBtn.disabled = false;
      }
    }
    replayForm.addEventListener("submit", (event) => { event.preventDefault(); void replay(); });
    await replay();
  } catch (error) {
    clear(body);
    body.appendChild(error instanceof ApiError ? errorBox(error.message, String(error.status)) : errorBox(String(error)));
  }
}

function renderReplay(result: ReplayResult): HTMLElement {
  const body = el("div");
  body.appendChild(el("div", { class: "row" },
    badge("historical view", "info"),
    badge(result.diff.answer_context_changed ? "answer context CHANGED" : "answer context unchanged",
      result.diff.answer_context_changed ? "warn" : "ok"),
    badge(`valid ${fmtTime(result.as_of_valid)}`, "muted"),
    badge(`recorded ${fmtTime(result.as_of_recorded)}`, "muted"),
  ));
  body.appendChild(el("p", { class: "note", text: result.view_label }));

  const split = el("div", { class: "split" });
  const sides: Array<["unguarded" | "guarded", string, typeof result.historical, string[]]> = [
    ["unguarded", `As known then (recorded ${fmtTime(result.as_of_recorded)})`, result.historical, result.diff.historical_citations],
    ["guarded", "As known now (same valid time)", result.current, result.diff.current_citations],
  ];
  for (const [cls, title, side, citations] of sides) {
    const col = el("div", { class: `compare-col ${cls}` }, el("h3", { text: title }));
    col.appendChild(el("div", { class: "row tight" }, ...citations.map((c) => badge(c, "muted"))));
    if (!side.context_chunks.length) {
      col.appendChild(empty("Nothing visible", "No eligible evidence at these coordinates."));
    } else {
      for (const chunk of side.context_chunks) {
        col.appendChild(highlighted(chunk.text, []));
      }
    }
    split.appendChild(col);
  }
  body.appendChild(split);

  body.appendChild(table(["difference", "chunks"], [
    ["only in the historical view", td(el("span", { class: "mono", text: result.diff.only_in_historical.join(", ") || "—" }))],
    ["only in the current view", td(el("span", { class: "mono", text: result.diff.only_in_current.join(", ") || "—" }))],
    ["unchanged", td(el("span", { class: "mono", text: result.diff.unchanged.join(", ") || "—" }))],
    ["revisions that changed the answer", td(el("span", { class: "mono", text: result.diff.revisions_changed.join(", ") || "—" }))],
  ]));
  body.appendChild(el("p", { class: "note caveat", text:
    "Replay reconstructs the memory layer only, and never re-promotes rejected or quarantined " +
    "content. Hidden model state is not replayable and no claim is made that it is." }));
  return card(`Replay — ${result.label}`, undefined, body);
}
