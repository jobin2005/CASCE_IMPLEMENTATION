---
name: casce-datagen
description: Use when asked to generate, extend, or batch-produce synthetic training scenarios/sessions for the CASCE cross-layer intrusion-detection GAT. Covers planning the batch, spawning generation workers, and gating the corpus before it scales — read this before writing a single scenario spec or spawning a worker.
---

# CASCE synthetic scenario batch generation

Read `datagen/scenario_spec.md` (format) and `datagen/scenario_spec.schema.json`
(machine schema) before authoring or reviewing any scenario spec — this
skill governs how a batch gets planned and executed, not the spec format
itself.

Written for a coding-agent harness with a parallel subagent/task
primitive (Claude Code's `Agent` tool, OpenCode's task tool, or
equivalent). Wherever this says "spawn a worker," use whatever your
harness calls launching an independent subagent.

`algorithm_3_abstract.py` currently has a `relation`/`rel` key mismatch
and a missing `label` attribute that make it emit zero Behavior nodes on
any real graph — a separate, already-tracked workstream, not something
this skill owns or blocks on. Its practical effect here: until that's
fixed, `validate_run.py`'s pipeline check (see "Prerequisite" below) can
only confirm correlation- and graph-structure-level correctness, not
anything about Behavior-node output. Know that when reading a "pass."

## Inputs this skill needs before it can plan anything

A vague request ("generate some training data") is tempting to just run
with — picking a plausible count, domain, and category mix yourself
keeps things moving. Don't guess when the request doesn't give you
enough to resolve it. But don't ask when you can resolve it yourself:
**ask only when the input can't be derived from the manifest
(`datagen/generated/manifest.jsonl`) and the available domain models.**
"Extend the corpus by 500 scenarios across all existing domains, fill
whatever's thin" gives you a count and domains directly, and "fill
what's thin" is a real instruction — read the manifest, find the
categories/domains under-represented, and plan against that. "Generate
some training data," with no count and no direction, doesn't resolve
that way — ask what's needed:

- **target count**
- **domains** — either stated, or "all domains with an existing model"
- **category / class-balance targets** — either stated, or derived from
  manifest gaps

**`mode` is the one input with a safe default: `pilot`.** Pilot runs a
few hundred samples and is hard-gated on the corpus-level checks below
before anything may scale. Treat an unstated mode as `pilot`, never as
`scale` — generating 10,000 samples before anyone has checked the
pilot for shortcuts is expensive and hard to walk back (retraining,
re-tuning thresholds against a corpus that turns out to be
contaminated), while running a pilot when scale was actually wanted
only costs one extra gate check.

## Prerequisite: domain models must already exist

Domain models (`datagen/domains/*.yaml` — table/column schema with
sensitive columns flagged, roles, per-role normal behavior) are
hand-authored once and must stay identical across the whole corpus:
"analyst role reading customer PII is abnormal" only works as a training
signal if every scenario across every invocation agrees on what's normal
for that role. If a domain model is missing, **do not draft one to keep
the batch moving** — a model improvised inside one worker's context, used
only for that worker's scenarios, silently reintroduces the
inconsistency the domain model exists to remove, and nothing downstream
will detect it because there's no cross-check that domain semantics
agree across runs. Stop and report which domain(s) lack a model. Domains
that do have one may still proceed — don't block a batch entirely over
one missing domain if others are ready.

## Prerequisite: the two CLI tools

- `datagen/codegen.py <run_dir>` — deterministic. Reads every spec under
  `<run_dir>/specs/`, allocates run-unique pids and one `LOGGING_START`
  clock offset for the whole run, writes `postgres_events.json` /
  `kernel_events.json` / `labels.csv`, and emits an expectation manifest
  (what node/edge types each event should produce) as a byproduct for
  `validate_run.py` to check against — the validator should not
  re-derive that expectation independently, or the two will silently
  drift apart over time.
- `datagen/validate_run.py <run_dir>` — runs the real
  `algorithm_1.run_one()` → `algorithm2.run()` (and, once fixed,
  `algorithm_3_abstract.abstract_session_graph()`) against `<run_dir>`
  and checks the "Validation" section of `datagen/scenario_spec.md`,
  including the matched-pair sibling/dimension check. Exits nonzero with
  which scenario/session failed and why.

If these don't exist yet, that's separate implementation work this
skill assumes is already done.

## Cross-layer scope: the invariant is per scenario, not per session

Every scenario (both classes) must contain at least one session with
real OS-layer activity — this is what keeps "OS activity present"
uninformative as a shortcut and forces the model to use cross-layer
evidence. It is easy to over-apply this to individual sessions instead:
a multi-session scenario like `privilege_abuse` can be entirely
SQL-only session-by-session (`CREATE ROLE ... SUPERUSER`, a config
change, an `UPDATE`) with no OS activity anywhere in it, and that's
still out of scope for this corpus, full stop. But inside a scenario
that *does* have at least one OS-layer session (e.g.
`multi_session_apt`'s recon and escalation sessions are pure SQL, its
exfiltration and cleanup sessions are not), the SQL-only sessions are
not just tolerated, they're useful: a session labeled malicious whose
only tell is the SQL itself, with no OS corroboration, teaches the model
that suspicious SQL matters on its own. Don't "fix" those sessions by
injecting incidental OS noise to make every session individually
cross-layer — that fabricates activity that didn't happen in the
scenario's own story and weakens the exact signal this design is trying
to produce.

## Matched pairs: authoring difficulty is a known hard case, not silent scope-narrowing

`matched_pair_id`/`matched_dimensions` (see the spec's closed dimension
vocabulary) are hardest to satisfy for multi-session attacks: a
`fixed: [process_tree_shape]` constraint on a 3-4 session
recon→escalate→exfiltrate→cleanup shape means the benign twin must share
that same multi-step structure, and "what legitimate workflow does three
sequential reconnections plus a cleanup step" doesn't have an obvious
answer. Two ways this goes wrong silently: inventing an implausible
benign cover story just to satisfy the shape (the model can learn to
detect the implausibility instead of the intended distinction), or
quietly narrowing the `fixed`/`varied` dimensions until something
benign-sounding fits (the pair stops actually testing what it was built
to test — this is now also a validator-enforced vocabulary, so a worker
can't silently invent an easier dimension, but it can still legitimately
struggle to fill the required ones). When a worker hits this, escalate
to the lead for a domain-specific cover story rather than resolve it
alone; the lead has visibility across the batch's domain models and
other workers' pairs that a single worker doesn't.

## Idempotency: check the manifest before assigning new work

Keep `datagen/generated/manifest.jsonl` (one row per scenario: family_id,
scenario_id, run_id, domain, category, class, rule_engine_relationship).
If it doesn't exist yet, treat that as an empty corpus, not an error — a
first invocation has nothing to check against. A later invocation
extending the corpus that ignores the manifest will gravitate toward the
same easy family shapes (the same read-then-curl exfiltration skeleton
with swapped identifiers) — new-looking scenarios that are near-
duplicates of existing families. That's invisible until the family-level
train/val/test split, where near-duplicate families land on both sides
of the split and quietly inflate validation scores. Before planning a
new batch, read the manifest and treat existing families as taken:
new assignments should extend category/domain/rule-engine-relationship
coverage the manifest is thin on, not repeat what's already there.
Update the manifest as runs complete, not only at the end.

## Unit of parallelism: one run directory per worker

A run directory (`datagen/generated/<run_id>/`) owns one pid namespace
and one clock offset, and confines whole families (see the spec). Two
workers assigned different run directories never touch the same file —
this is what makes them safe to run fully in parallel with no
coordination between them. This is also why the unit isn't the
individual scenario (too fine-grained: every scenario would round-trip
through the lead for no isolation benefit) or the whole batch
(serializes work that has no reason to be serial). Keep both halves of a
matched pair, and every scenario in a family, in the same run directory
— `validate_run.py` enforces the matched-pair sibling check locally per
run, and splitting either across workers would require validation
against a directory a worker doesn't own.

**This isolation makes writes safe; it does not make content diverse.**
Independent workers given similar category assignments will tend to
converge — the same table names, the same IP ranges, the same filenames
— which reproduces the near-duplicate problem that already disqualified
using live captures for training, one level up. Give each worker's
assignment slice its own differentiating parameters (attacker
infrastructure, data volumes, time windows, specific domain entities) up
front, rather than relying on the corpus-level near-duplicate check to
catch convergence after a full batch has already been spent generating
it.

## Lead's job

1. **Check inputs, domain-model prerequisites, and the manifest first**
   (above). Don't start planning against a domain that has no model.
2. **Build the assignment plan and write it to
   `datagen/generated/plan_<batch_id>.json` before spawning anyone.**
   This is a distinct artifact from `manifest.jsonl`: the manifest is
   the durable, cross-invocation record of what's already been
   generated (what the idempotency check in the previous section reads
   against); the plan is scoped to this one invocation — the work items
   this batch intends to produce, with a status the lead updates live as
   workers report. Holding the plan only in your own reasoning, across a
   batch with several concurrently-running workers and multiple rounds
   of corpus-level correction, is exactly the situation where a category
   or a matched-pair obligation silently drops. Externalize it. At
   minimum, one entry per run directory:
   ```json
   {
     "run_id": "run_041",
     "status": "pending",
     "domains": ["banking"],
     "assignments": [
       {"category": "exfiltration_delayed", "class": "malicious",
        "count": 4, "family_id": "banking_exfil_delayed_09",
        "matched_pair_id": "banking_exfil_delayed_09_pair",
        "rule_engine_relationship": "malicious_false_negative",
        "differentiating_params": {"attacker_ip_range": "45.33.x.x", "data_volume": "large"}}
     ],
     "worker": null,
     "validated": false
   }
   ```
   Build the assignments themselves against what the manifest shows is
   missing: which category/domain/matched-pair/family slice each run
   directory owns, with concrete differentiating parameters per slice
   (see "diverse" above). Every category and every domain should appear
   in more than one run directory. Include a deliberate mix of
   `rule_engine_relationship` values — a corpus where every scenario
   `agrees` with the existing rule engine can pass every check below and
   still leave the GAT nothing to contribute; the exact proportion of
   `benign_false_positive`/`malicious_false_negative` to target is set
   from the pilot's own rule-engine-alone baseline score.
3. **Spawn one worker per `pending` plan entry, in bounded batches**
   (5-10 concurrent — you need to be able to review what comes back, not
   just dispatch it), and flip each to `in_progress` as you spawn it.
   Give each worker its run_id, its assignment slice including its
   differentiating parameters, and the relevant domain model(s). Tell it
   not to touch any other run directory.
4. **Independently confirm `validate_run.py`'s exit status per run
   directory yourself**, and record it in the plan entry's `validated`
   field — a worker's report that it passed is a claim, not the
   evidence; the evidence is the exit status, and checking it costs one
   command, not a re-derivation of the worker's validation work.
5. **Run corpus-level checks yourself** once a batch of runs is in —
   these are cross-run statistical checks no single worker's directory
   can answer alone:
   - node-type-presence × label contingency table: a binary
     presence-per-node-type vector against the label, checked for
     independence (chi-square or Fisher's exact — pick one and keep it
     consistent across invocations; refine the exact test at pilot if
     needed, but don't switch tests between checks of the same corpus).
   - primitive/template-fires-in-only-one-class check.
   - **varied-dimension shortcut check**: across all matched pairs, no
     single `matched_dimensions.varied` entry may dominate, and no
     varied dimension's actual value may correlate with class — a
     `varied: [role]` pattern where malicious pairs consistently get one
     role and benign pairs another reintroduces role-as-label exactly
     the way matched pairs exist to prevent.
   - family-level near-duplicate check before any train/val/test split.
   - pilot only: the shortcut-baseline gate (node-presence-only,
     bag-of-primitives, SQL-only, OS-only, graph-size-only,
     rule-engine-alone, Behavior-masked GAT). **Report the exact scores
     to the user rather than judging "close enough" yourself** — where
     the line is between "the shortcut approaches the full model" and
     "it doesn't" is a threshold that should be set from the pilot's own
     numbers, together with the user, not decided unilaterally per
     invocation.
6. **A pilot that hasn't cleared step 5 blocks scaling — that's not
   advisory.** If a check fails, trace it to the run(s)/category
   responsible, mark the affected plan entry `failed` with the reason,
   and add a fresh plan entry to regenerate it (not a special-cased
   retry to the original worker — at pilot scale there's no evidence yet
   that reusing the same worker's context is worth the extra machinery)
   rather than patching the merged corpus centrally.
7. **Update the plan entry's status to `done` and append its scenarios
   to `manifest.jsonl`** as each run lands, not only when the whole
   batch finishes — an interrupted batch should still leave both an
   accurate plan (what's done, pending, or failed) and an accurate
   manifest (what actually exists) behind it.

## Worker's job, per assigned run directory

1. Read the domain model(s) and this run's assignment, including its
   differentiating parameters.
2. Author each scenario as `datagen/generated/<run_id>/specs/<scenario_id>.yaml`.
   Use real literal SQL and real literal shell command lines — never an
   abstracted action taxonomy (see `datagen/scenario_spec.md` for why).
3. Before generating, do a fast self-check — this is a pre-flight to
   catch obvious mistakes before spending a codegen/validate cycle on
   them, not a substitute for schema validation or `validate_run.py`,
   which are the actual gate: does every event have real content (no
   placeholders), does each assigned category's defining structural
   feature actually show up (an `exfiltration_delayed` scenario needs a
   real gap between read and send, not two adjacent steps), and does
   this scenario satisfy the cross-layer scope invariant above (skip
   this check only for a deliberate `anchor: none` negative-control
   fixture explicitly in the assignment)?
4. Run `datagen/codegen.py <run_dir>`, then `datagen/validate_run.py <run_dir>`.
5. On failure, revise the spec and regenerate — never hand-edit the
   generated JSON, since the spec is the only thing that stays the
   source of truth. If a scenario still fails after a few attempts, or
   hits the matched-pair authoring difficulty above, escalate to the
   lead rather than dropping it or forcing something implausible.
6. Report to the lead: scenario count, pass/fail per scenario, which
   assigned categories/matched pairs/rule-engine-relationship targets
   landed, and any escalations.

## Settled constraints — do not relitigate these mid-batch

- Malicious and benign scenarios draw from the same domain model and
  action palette; no primitive or template may appear in only one
  class. An LLM-invented "badness vocabulary" used as the label would
  just re-encode the existing rule engine into the data.
- `anchor: none` sessions are produced only when a worker's assignment
  explicitly calls for a negative-control fixture — they are never
  counted toward a worker's scenario-count target, because they never
  resolve to a session in Algorithm 1, so counting them would inflate
  the apparent corpus size with samples the GAT never actually sees.
- The `"label"` node-attribute content (normalized-literal text vs.
  abstracted category) is decided from the pilot batch's own data, not
  upfront. Nothing here depends on which way that resolves.
