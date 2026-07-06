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

**9 logged; 1 more before the first recalibration.**

Early signal (pre-recalibration, not yet acted on): no task has needed rework
once its verifier was in place; the two bugs the private-repo suite caught were
stopped *by the verifier before merge*, which is the mechanism working, not
rework. Security-control and cross-repo-sweep classes are trending toward
staying at their earned rungs.
