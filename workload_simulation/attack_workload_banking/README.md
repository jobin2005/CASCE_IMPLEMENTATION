# 4D OOD attack workload — banking adaptation

Adapted from `../attack_workload/*.sh` for the live out-of-distribution ("4D") test
described in `EXPERIMENTS.md` → "4D: plan". See `../ood_4d/sample_sessions.sh` for the
adaptation rule this follows: connection, table names and label change; the attack
logic (the SQL / shell command) does not.

Every script takes `REPEAT` as an env var (default 1) — run the same script three times
with `REPEAT=1`, `REPEAT=2`, `REPEAT=3` for the task's three repeats, rather than three
copies of each file. `manifest.jsonl` already has all three repeats' entries.

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

`new_technique: false` only for the backdoor-role/multi-stage group, matching the task's
own classification ("similar to training") and the sample's note.

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

**8 legacy scripts the original task brief never named** are not adapted and not in
`manifest.jsonl`: `attack_concurrent_dual_malicious.sh`, `attack_concurrent_mixed.sh`,
`attack_db_unauthorized_read.sh`, `attack_exfiltration.sh`,
`attack_exfiltration_alt_process.sh`, `attack_exfiltration_delayed_2s.sh`,
`attack_exfiltration_delayed_30s.sh`, `attack_multi_stage_apt.sh`. All 8 touch the
database (unlike `attack_os_priv_escalation.sh` above) and don't map cleanly onto a
named group. Pending a decision on whether to include them.
