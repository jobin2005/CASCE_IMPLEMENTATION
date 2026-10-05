# 4D OOD attack workload — banking adaptation

Adapted from `../attack_workload/*.sh` for the live out-of-distribution ("4D") test
described in `EXPERIMENTS.md` → "4D: plan". See `../ood_4d/sample_sessions.sh` for the
adaptation rule this follows: connection, table names and label change; the attack
logic (the SQL / shell command) does not.

Every script takes `REPEAT` as an env var (default 1) — run the same script three times
with `REPEAT=1`, `REPEAT=2`, `REPEAT=3` for the task's three repeats, rather than three
copies of each file. `manifest.jsonl` already has all three repeats' entries.

**Validated so far: static checks only, nothing live.**
`bash -n` on all 30 scripts (all pass); all 102 `manifest.jsonl` lines parse as JSON;
grepped all 30 scripts for every `psql` invocation having a `PGAPPNAME=` prefix on the
preceding line (34 invocations found, 34 labelled, 0 missing). None of this has been run
against a live Postgres instance — no proof yet that a statement behaves as expected once
it reaches `casce_banking`, only that the scripts are syntactically sound and every
session is labelled. The live run on Adithyan's machine is what actually tests this.

## What's here

34 distinct attack sessions (102 manifest lines across 3 repeats), covering every group
and script named in the original task brief:

| Group | Scripts | Sessions | Role | New technique? |
|---|---|---|---|---|
| `exfiltration` | 15 of the 20 `attack_exfil_var_*` (see below) | 15 | teller | yes |
| `os_command` | all 7 `attack_priv_var_*` | 7 | teller | yes |
| `sql_injection` | all 4 `attack_sqli_*` | 4 | teller | yes (see note on `sqli_role`) |
| `reverse_shell` | `attack_reverse_shell` | 1 | teller | yes |
| `sabotage` | `attack_sabotage` | 1 | dba | yes |
| `backdoor_role` | `attack_privilege_abuse` (3 psql calls = 3 sessions) | 3 | dba, hacker×2 | no |
| `multi_stage` | `attack_multi_session_apt` (3 of its 4 stages) | 3 | dba | no |

**Rule used to set `new_technique`:** applied at whole-script granularity, matching the
task brief's own per-script group list, not per-statement. `false` only for the
`backdoor_role`/`multi_stage` group (`attack_privilege_abuse`, `attack_multi_session_apt`),
because the brief classifies that whole group "similar to training" and the sample's note
narrows the carve-out to the same two techniques: backdoor `CREATE ROLE` and plain-curl
exfiltration. Every other session here is `true`. One known rough edge from applying this
per-script rather than per-statement: `attack_sqli_role.sh`'s payload is itself a backdoor
`CREATE ROLE`, but it's filed under `sql_injection`/`true` because the brief's script list
puts all four `attack_sqli_*` scripts there — see the note on it below. Audit point: if
Adithyan's scoring needs this finer-grained, it isn't captured by the current manifest.

## Judgment calls made without asking (documented here so they're easy to revise)

- **Exfiltration subset (15 of 20).** The task asked for "about 10-15"; the 20 originals
  are 5 compression tools (gzip, bzip2, base64, tar, zip) × 4 transports (curl, wget, nc,
  socat). Kept curl/wget/nc for every compression tool, dropped all 5 socat variants —
  an arbitrary cut, not a judgment that socat matters less. Swap any of these back in by
  copying the pattern from `../attack_workload/attack_exfil_var_{3,7,11,15,19}.sh`.
- **Role per script.** The legacy scripts ran everything as `-U postgres`. None of the
  five banking roles is superuser, so every script needed *some* role assigned, and the
  brief only gave two worked examples (teller for exfiltration/SQLi, dba for backup).
  Used **teller** as the default for everything except the destructive/role-creation
  attacks (sabotage, privilege abuse, multi-stage APT), which use **dba** — the
  compromised-admin-account reading is the more coherent story for those three. This is
  a guess, not a derived fact; the manifest's `role` field makes it a one-line change per
  session if that's wrong.
- **`attack_sqli_role.sh` grouping.** Its payload (`CREATE ROLE sqli_admin SUPERUSER`) is
  identical in kind to the backdoor-role attacks, but the task's own script list puts all
  four `attack_sqli_*` scripts under `sql_injection`/"New", so it's filed there, not under
  `backdoor_role`. Flagging the tension rather than silently resolving it either way.
- **`attack_privilege_abuse.sh`, steps 2–3, will likely never produce a session.** Step 1
  creates role `hacker`; dba has `CREATEROLE` but cannot grant `SUPERUSER` (only a real
  superuser can), so step 1 is expected to be denied. Steps 2 and 3 then try to connect
  *as* `hacker`, which was never created — that connection is expected to fail at
  authentication, before the Postgres hook can attach, so there may be no
  `session_labels.jsonl` entry for those two keys at all. Kept them as written anyway
  (matches "attack logic stays as written"), rather than quietly rewriting them to
  connect as an existing role.
- **Sabotage target table.** `pgbench_history` → `transactions` (its closest banking
  equivalent, per the sample's own table-mapping note). No banking role has DROP on any
  table, so this is expected to be denied too.
- **`pgbench_tellers` has no banking equivalent** (per the sample's note) — the one
  script that touched it (`attack_privilege_abuse.sh`'s third call) now targets
  `accounts` instead.

## Excluded, not adapted

- **`attack_os_priv_escalation.sh`** — zero `psql` calls, pure OS shell. No Postgres
  session exists for the hook to attach to, so CASCE cannot see this activity either
  way; out of scope for a tool that only reasons about database sessions.
- **Stage 4 of `attack_multi_session_apt.sh`** (`rm -f /tmp/some_fake_log.log`, no psql
  call) — same reason, excluded from the 3-session adaptation above.

## Still open — not decided here

**8 legacy scripts the original task brief never named** are deliberately left out of
this folder and `manifest.jsonl` — not adapted "just in case." Default is exclude,
because adding one later is a few lines; pulling a script's sessions and labels back out
after Adithyan has already captured and scored a live run is not. One line per script,
with a proposed group and the specific reason it wasn't just mechanically adapted like
the 30 above — each needs a yes/no from Adithyan19, who scoped and will run this:

| Script | Would map to | Why it's not a mechanical adaptation |
|---|---|---|
| `attack_exfiltration.sh` | exfiltration | Near-identical to `exfil_gzip_curl` (same gzip+curl, LIMIT 500 vs 10) — likely the base case the 20 `_var_*` variants were derived from. Confirmed it did **not** feed training (`EXPERIMENTS.md`: "`attack_workload/*.sh` ... were not used in any recorded run"), so it's not an OOD-contamination risk. Left out only because it's redundant with a variant already included, not for a correctness reason. |
| `attack_db_unauthorized_read.sh` | — (no group fits) | Pure SQL read, no OS-layer activity at all — closer to a different test ("can SQL alone trigger a CASCE alert, with zero cross-layer corroboration") than to any attack group in the brief. Trivial to adapt if that's a question worth asking, but it's a different question. |
| `attack_concurrent_dual_malicious.sh` | — (no group fits) | Two attacks fired in parallel, backgrounded (`&`/`wait`), hitting the DB at the same instant. Whether `algorithm_1.py`'s ppid-chain correlator attributes each spawned OS process back to the right one of two concurrently-open backends is an open question about the correlator, not something a label change settles. |
| `attack_concurrent_mixed.sh` | — (no group fits) | Same concern as above, one benign session and one malicious session overlapping instead of two malicious ones. |
| `attack_exfiltration_delayed_2s.sh` | exfiltration (maybe) | Script's own comment: "test temporal similarity algorithms." Same gzip+curl payload as `exfil_gzip_curl`, with a 2s `sleep` spliced in before the network call. Tests the correlator's time window, not whether the classifier generalizes to a new attack type — a different experiment from 4D's stated purpose. |
| `attack_exfiltration_delayed_30s.sh` | exfiltration (maybe) | Same as above, 30s delay — "stress-test temporal linkages" per its own comment. |
| `attack_exfiltration_alt_process.sh` | exfiltration (maybe) | Script's own comment: "Tests semantic similarity algorithms against structural signatures." Same exfil, but via a `python3 -c` one-liner instead of gzip+curl — tests process-attribution/representation robustness, not attack-type generalization. |
| `attack_multi_stage_apt.sh` | multi_stage (maybe) | Not a duplicate of the in-scope `attack_multi_session_apt.sh` — it's the same recon → escalate → exfil sequence packed into **one continuous psql session** (a heredoc of 4 statements) instead of three separate reconnects. That's a structurally different test (can one session's graph alone carry the whole APT story?) from the in-scope script (can three separate sessions be linked across reconnects?). Worth doing, but as its own thing, not folded into the 3 multi-stage sessions already in `manifest.jsonl`. |

**Training-data provenance — resolved, not an open question.** The concern that any of
these 8 (or the 30 already adapted) might have fed the model's training data and so
inflate the "unseen attack" claim is checked against `EXPERIMENTS.md` directly: the
synthetic training corpus comes entirely from `datagen/generate_batch.py`'s 13 YAML
templates, and the legacy `attack_workload/*.sh` scripts — all 44, named and unnamed —
"were not used in any recorded run." Some of the 30 already-adapted scripts resemble a
training template in technique (plain curl exfiltration, backdoor `CREATE ROLE`) — that's
exactly what `new_technique: false` already flags for those sessions — but none of the 44
scripts is a training *source*.

**Pre-run question for Adithyan — not something scoring can fix after the fact.**
Several adapted sessions (SQLi-copy/role, sabotage, the privilege-abuse steps) are
expected to be denied by Postgres before any OS-layer activity happens.
`session_labels.jsonl` records ground truth as Malicious regardless of whether the
statement succeeded. Checked `pg_telemetry.c` directly: `casce_ProcessUtility` and
`casce_ExecutorStart` both log the statement (event_type `ProcessUtility` /
`ExecutorStart`) *before* calling into Postgres's own execution path, so a denied
statement still gets one log line — but the hook never records the error, the SQLSTATE
(e.g. `42501 insufficient_privilege`), or any outcome field, and there's no matching
`ExecutorEnd`/second event when the statement aborts. So a denied session and a session
that ran fully and was simply missed are indistinguishable in `postgres_events.json`
after the fact — there is no field to recover this from once the run is over.

If this distinction matters for the 4D results table, it has to be captured **at run
time**, not patched into scoring later. The cheapest fix: have whatever runs these
scripts capture each `psql` call's own exit code (and ideally stderr) and write it
alongside the manifest, keyed by `key`+`repeat` — `psql -c` returns nonzero when the
server returns an error for that statement, so this needs no hook change. Not built into
these 30 scripts pre-emptively: adding it is a legitimate design choice (per-script
capture here vs. a shared wrapper vs. changing the hook itself) that's Adithyan's call,
not mine to make by default.
