# 4D OOD workload — status and what happens next

For Adithyan19, and whoever else picks this branch up. Detail, judgment calls and
evidence are in `README.md` in this folder — this note is the short version: what's
built, what isn't, and what has to be decided before anyone runs this live.

## What's built

30 of the 35 legacy scripts the task brief named are adapted to `casce_banking` (banking
roles, banking tables, `PGAPPNAME` labels), giving 34 distinct attack sessions, in
`workload_simulation/attack_workload_banking/`. `manifest.jsonl` has all 34 × 3 repeats
= 102 labelled entries, matching the schema fixed by `../ood_4d/sample_sessions.sh`. The
other 5 — the socat exfiltration variants (`attack_exfil_var_{3,7,11,15,19}.sh`) — were
cut to land in the brief's "10-15" count, a reversible scope choice, not a correctness
one; see decision 3 below.

Each session's `new_technique` flag (does this resemble a training template, or not) was
set by a stated rule, not case by case — see `README.md` → the rule, and the one rough
edge it has (`attack_sqli_role.sh`). Worth checking before trusting any OOD-vs-near-OOD
split in the results.

Checked: every script passes `bash -n`; every manifest line parses as JSON; every `psql`
call carries a `PGAPPNAME` label (34/34); none of the 30 feeds multiple statements
through `-f` or a heredoc (grepped for both, zero matches) — all 30 use `psql -c`, one
statement per call. That's it — static checks only, no live run.

## What isn't built, and why

- **8 legacy scripts are deliberately left out** of this folder and the manifest —
  not adapted "just in case." Each one, a proposed group, and the specific reason it's
  not a mechanical adaptation (near-duplicate, a concurrency question, SQL-only with no
  OS-layer signal, or a different experiment than 4D's) is in `README.md` → "Still open."
  Each needs a yes/no from you.
- **No benign sessions here.** This folder is attack sessions only. Per the original
  task brief, backup/maintenance/reporting/app-traffic benign sessions are prepared and
  run separately ("I can prepare and run these myself"). If that's still the plan,
  confirm it's actually covered somewhere before this run — without benign traffic
  alongside these attacks, 4D measures detection but not false positives.
- **No mechanism exists yet to tell a denied attack from a missed one.** Checked
  `pg_telemetry.c` directly: it logs a statement before checking whether it's allowed,
  and never records the error or SQLSTATE. A session denied by Postgres (expected for
  several of the 34 — SQLi-copy/role, sabotage, privilege-abuse) and a session that ran
  and was simply missed look identical in `postgres_events.json` afterward. Worse: a
  denied attack still shows as SQL-layer activity, so if the model flags it anyway, the
  results table counts a catch that never happened — detection rates read high until
  this is fixed.

## Before you run anything, you need to decide

1. **The 8 excluded scripts** — include any of them, or leave them out? Table with
   reasoning is in `README.md`.
2. **How to capture denied-vs-ran at run time.** This can't be recovered from logs after
   the fact — it has to be captured while the scripts run, per call, not once per
   session (a multi-call script like `attack_privilege_abuse.sh` can have one call denied
   and another succeed). A nonzero exit code only tells you the call *failed* — a typo'd
   table name from this adaptation or a missing object fails the same way as a real
   permission denial. **stderr is what tells denial apart from breakage** (look for the
   SQLSTATE, `42501 insufficient_privilege` on a real denial). So: capture both exit code
   and stderr per call, keyed by `key`+`repeat`. This is reliable for every script in
   this folder — all 30 use `psql -c`, one statement per call (checked, see above) — but
   not in general: anything fed through `-f`/a heredoc needs `-v ON_ERROR_STOP=1` to make
   a mid-script denial visible at all, and that itself changes the attack (later
   statements stop running). Your call on how to wire this in, not a default I picked.
3. **The 5 cut socat exfiltration variants** — put any back in, or leave the 15 as is?
   Reversible either way; see `README.md` for which 5 and why they were cut.

## Not run

This is script adaptation only. Nothing here has executed against a live database.
Live execution needs your container (`casce_banking`, the roles, `logger.sh` capturing).
