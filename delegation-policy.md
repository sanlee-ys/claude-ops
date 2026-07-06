# Delegation policy

**Status:** v0 — 2026-07-06. The initial policy per
[`decisions/ADR-003-delegation-maturity.md`](decisions/ADR-003-delegation-maturity.md)
Phase 3, step 1. Deliberately provisional: the experiment log below is the
evidence that recalibrates it (step 3), and no class is promoted a rung without
a verifier behind it.

## The gate rule

The autonomy a class of work earns is set by the strength of the *automated
verifier* that covers it — not by trust or feel. A class with a strong verifier
(a test suite, a QA gate, an eval) can run autonomously because a red build, not
a human, catches the failure. A class with no verifier stays at plan-and-approve,
or gets a verifier built first. This is the Phase 1/2 lesson made general:
`mobile-qa.cjs` earned the portfolio site its autonomy; the credential guard's
adversarial suite earned the guard its.

## Autonomy ladder

- **L0 — Plan & approve.** The agent plans; the human approves before execution.
  The default when no automated verifier covers the work. The human is the gate.
- **L1 — Autonomous + verify.** The agent executes end-to-end; an automated
  verifier gates the result; the human reviews the summary, not each step.
  Requires a verifier covering the class.
- **L2 — Orchestrated fan-out.** The agent orchestrates sub-agents under an
  explicit token cap; verifier(s) plus a single integrator gate the result; the
  human sets the cap and reviews outcomes. Requires a verifier *and* a cap.

## Task class → verifier → earned level

| Task class | Verifier that gates it | Earned level |
|---|---|---|
| Prose / docs (CLAUDE.md, ADRs) | redline-guard (public repos), the links rule, human read | L1 mechanical · L0 judgment rewrites |
| Security-control code | adversarial test suite + CI | L1 |
| Static site / layout | `mobile-qa.cjs` + link-check + CI | L1 |
| Classifier / eval code | the eval harness + pytest + CI | L1 |
| Cross-repo mechanical sweep | `sync-shared-blocks.py --check` + per-repo CI | L2 |
| Research / audit fan-out | adversarial verify pass + human review; cap enforced by `fanout-guard.py` | L2 |
| Novel design / architecture | none (judgment) | L0 |

## Tier mapping

Model tier follows the same measure-first principle (SYS-002): **Fable judges /
verifies · Opus orchestrates · Sonnet executes**, and every L2 fan-out carries a
token cap (`fanout-guard.py` blocks an uncapped one). Escalate a tier only where
the task earns it — same discipline as autonomy.

## Experiment log

Per ADR-003 Phase 3 step 2: assign a level up front, log the outcome
(accepted / minor rework / major rework). Recalibrate once ≥10 are logged —
classes with a clean record move up a rung; classes generating rework get a
verifier before more autonomy. Repo names are omitted where private.

| Date | Task | Class | Level | Outcome |
|---|---|---|---|---|
| 2026-07-06 | Posture note: rotation-not-cleanup + guard-coverage fix | prose/docs | L1 | accepted |
| 2026-07-06 | 12-repo CLAUDE.md rule-surface audit | research fan-out | L2 (2M cap) | accepted — drove the plan, no rework |
| 2026-07-06 | Build canonical block + sync/drift tooling | security/infra code | L1 | accepted — self-verified (`py_compile` + `--check`) |
| 2026-07-06 | Single-source the links block across 10 repos (incl. resolving 3 squash/advance branch divergences) | cross-repo sweep | L2 | accepted — self-caught a block-size overestimate before commit |
| 2026-07-06 | Targeted doc refresh: compress an enforced rule + refresh a stale scope section | docs w/ judgment | L0→L1 | accepted after 2 approvals |
| 2026-07-06 | Amend ADR-003 Phase 2 to measured reality | prose/docs | L1 | accepted |
| 2026-07-06 | Wire the shared-block drift check into CI | security/infra code | L1 | accepted — proven by a live run |
| 2026-07-06 | Fix a stale generated site + add a regeneration drift gate (learning-notes) | static site / CI infra | L1 | accepted — new gate went green live, would have caught the drift |
| 2026-07-06 | Build the private-repo guard, layers A+B (slug allowlist + disclosure phrases) | security-control code | L0→L1 | accepted — plan approved first; adversarial suite caught 2 real bugs pre-merge, live gate proven in CI |
| 2026-07-06 | Build the private-repo guard, layer C (local pre-commit for bare names) | security-control code | L0→L1 | accepted — smoke-tested end-to-end (decoy blocked), adversarial suite green in CI |

**10 logged — first recalibration below.**

## Recalibration 1 (2026-07-06)

**Basis:** 10 outcomes, all accepted, zero post-verifier rework.

**Honest caveat on the sample.** All 10 come from a single session, one operator,
one day. That is low diversity — no independent reviewer, no second executor
model, and "accepted" was partly self-assessed. So this round demonstrates the
*mechanism* (a verifier catches issues before merge — twice, concretely) more
than it proves broad autonomy is safe. Promotions are therefore conservative: a
class moves only with n ≥ 3; smaller classes stay put and keep logging.

| Class | n | Rework | Verdict |
|---|---|---|---|
| security-control / infra code | 5 | 0% | **Confirmed at L1** — each shipped with its own adversarial suite / CI gate as the verifier. The class that satisfies the exit criterion (≥1 class at full autonomy, <20% rework). |
| prose/docs (mechanical) | 2 | 0% | **Confirmed at L1** — redline-guard + human read as the verifier. |
| docs w/ judgment | 1 | 0% | Hold at L0 — clean but n=1; approve-first is cheap insurance where correctness is a matter of taste. |
| research fan-out | 1 | 0% | Hold at L2 (capped) — the token cap stays mandatory. |
| cross-repo sweep | 1 | 0% | Hold at L2 — n=1. |

No class generated rework, so none needs verifier-remediation this round. The two
bugs the private-repo suite caught were stopped *before merge* — the verifier
working, not rework.

**Next round:** log across more sessions and executor models (diversity is the
missing axis) before any further promotion; revisit at ~20 outcomes, or
immediately if a class first generates rework.

**Phase 3 exit criterion — met.** Written policy grounded in ≥10 outcomes; one
class (security-control) running at full autonomy with 0% rework; every
confirmation tied to a named verifier, and the un-promoted classes held for lack
of evidence, not feeling.
