# Contributing

Thanks for looking at this. A few things specific to a security project are worth knowing before you
open a pull request.

## Ground rules that are not negotiable

1. **No new network dependency in the default path.** `make setup`, `dev`, `smoke`, `test`, `eval`,
   `verify` and `screenshots` must all work with no API key, no cloud account and no outbound
   request. Optional adapters are fine; a required one is not.
2. **Only synthetic data.** Attack payloads must be inert strings using reserved `.invalid` or
   `.example` hosts. No real personal data, no working exploit, no resolvable attacker
   infrastructure, no copied text from a real company's policy or a real incident.
3. **A security test is never skipped.** `scripts/assert_no_skipped_security.py` runs in CI and
   fails the build if the security suite skipped anything or ran nothing.
4. **Evidence, not assertion.** If you claim a gate passes, `docs/ACCEPTANCE_STATUS.md` must name
   the command you ran and quote what you observed. "Looks right" is not a status.

## Where the security decisions live

Everything is in `packages/memory_firewall/memory_firewall/`. The HTTP API and the SDK are thin
shells over `MemoryFirewallEngine`, deliberately, so there is exactly one implementation of every
decision and the two surfaces cannot drift. If you find yourself adding a policy check in
`apps/api/`, that is the signal it belongs in the engine instead.

`tests/integration/test_route_parity.py` exists because the two HTTP adapters *did* drift once, and
the drift was an unauthenticated credential disclosure. Keep it passing.

## Changing the detector

The detector is the part most likely to attract well-meaning changes that make the numbers worse.

- **Add techniques, not strings.** A rule that matches one dataset case is overfitting. A rule that
  matches a *technique* will also catch the held-out split.
- **Run `make eval` before and after**, and put both numbers in your PR. Recall going up while
  benign false-quarantine also goes up is usually a bad trade, and the scorecard will show it.
- **Watch the held-out split.** `heldout_perturbation` exists to catch tuning-to-the-test. A widening
  gap between it and `primary` is the thing to explain.
- **Never weaken the quotation mitigator to raise recall.** Containment alone (quotes, a code fence)
  must never be sufficient to downgrade a finding — that was a real evasion route, and
  `tests/unit/test_detector_rules.py::test_example_cue_without_counter_instruction_does_not_mitigate`
  is there to stop it coming back.

## Changing the retrieval guard

`_GUARDED_SQL` in `retrieval.py` is the single most security-relevant string in the repository.
Every predicate in it is asserted by
`tests/security/test_bypass_surface.py::test_the_guard_sql_contains_every_required_predicate`, and
every predicate has a matching mode in `memory_firewall.testing.BYPASS_MODES` that forces poison
past it. **If you add a predicate, add a bypass mode for it.** If you remove one, explain why in
`docs/DECISIONS.md`.

The guard must stay fail-closed: any exception returns an empty result, never an unguarded one.

## Before you open a PR

```bash
make test      # 302 tests, 0 skipped
make eval      # and paste the before/after numbers
make verify    # the release truth source
```

If `make verify` reports BLOCKED checks in your environment, that is fine — say so. Do not mark a
blocked check as passing.

## Honesty is the feature

This project's credibility rests on its limitations being stated as clearly as its results. If you
find something that does not work, the most valuable contribution is documenting it precisely —
including in `docs/RED_TEAM_REVIEW.md` if you broke something. A finding is worth more than a fix
that hides it.
