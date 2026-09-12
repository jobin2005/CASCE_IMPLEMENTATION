# codegen.py and validate_run.py — technical specification

Spec version: 1.0
Date: 2026-09-12
Status: implementation-ready

Both tools operate on a single run directory (`<run_dir>`) that contains
`specs/*.yaml` scenario files and (after codegen) the generated log files.
They are deterministic, stateless CLI scripts with no inter-run side effects.

---

## 1. codegen.py

### 1.1 Invocation

```
python datagen/codegen.py <run_dir>
```

`<run_dir>` is an absolute or relative path to a directory that already
contains `specs/*.yaml`. codegen writes its output files into `<run_dir>`
itself, overwriting any prior generation.

### 1.2 Input: scenario specs

Read every `*.yaml` file under `<run_dir>/specs/`, sorted lexicographically
by filename. Parse each against `datagen/scenario_spec.schema.json` and the
rules in `datagen/scenario_spec.md`. A schema-invalid file is a hard build
error (see section 1.9).

Collect all parsed scenarios into a single ordered list. The remainder of
this section describes processing that list into output files.

### 1.3 PID allocation

Allocate a single run-wide PID namespace. PIDs must be unique across the
entire run (all scenarios, all sessions, all processes).

**Allocation order**: process scenarios in lexicographic filename order;
within each scenario, process sessions in list order; within each session,
process events in list order.

**What gets a PID:**

1. **Backend PID** — one per session. This is the `backend_pid` that
   appears on every postgres event for this session, and the root of the
   ppid chain for all kernel events in the session. For `anchor: db` and
   `anchor: synthetic` sessions, this pid is registered in Algorithm 1's
   `active_sessions` map when the first postgres event for this session
   arrives. For `anchor: none` sessions, the backend_pid is still
   allocated (kernel events need a ppid root) but no postgres event is
   emitted for it, so Algorithm 1 never registers it — this is the
   mechanic by which `anchor: none` events expire in the pending buffer.

2. **Spawned process PID** — one per explicit `process` event, and one per
   process implied by a `COPY ... TO PROGRAM '<cmd>'` SQL event's shell
   parse (see section 1.5).

3. **Implicit process PID** — for `file` and `connect` events whose
   `parent` references a `process` step (not needed when the parent is a
   sql step — the kernel event's `pid` is the parent process's pid and
   `ppid` is already set by the parent chain). See section 1.6 for when
   an additional process node is required.

**PID range**: start at 20000 (avoids collision with realistic system pids
that a reader might confuse with real data). Increment by 1 for each
allocation. The specific start value is a recommendation — the invariant
is uniqueness within the run, and that Algorithm 1's ppid-chain walk
(D_MAX=8 hops) can reach the backend_pid from any leaf process.

**ppid chain construction**: every spawned/implied process must have its
`ppid` set so that walking the ppid chain (child → parent → ... → backend)
takes at most D_MAX=8 hops. codegen must verify this at allocation time
and emit a hard error if a scenario's process tree exceeds 8 levels of
nesting below the backend_pid. The chain must be:

- For `process` events with `parent: <step_id>` → ppid = the PID
  allocated to the step referenced by `parent`.
- For `process` events with no `parent` → ppid = this session's
  backend_pid.
- For processes implied by shell-parsing a `COPY ... TO PROGRAM` → the
  first process in the pipeline has ppid = this session's backend_pid
  (Algorithm 2's `find_connection_rule` uses the `pending_spawn_source`
  mechanic for the Query→first-child hop, then ppid lineage for
  subsequent hops). Each subsequent process in a pipeline has ppid = the
  previous process's pid.
- For `file` and `connect` events → ppid and pid follow their `parent`
  step's process (see section 1.6).

### 1.4 Clock and timestamps

**Run-level clock offset**: codegen picks a single `LOGGING_START`
wall-clock timestamp for the run. This is the wall-clock instant that
corresponds to the first kernel event's monotonic-nanosecond value. It
is written as the marker record at the top of both `kernel_events.json`
and `postgres_events.json`.

The value itself: use the current date (or a configurable `--date`
argument, default today) combined with a time earlier than any scenario's
`time_of_day`, e.g. midnight (`00:00:00`) of the generation date. The
exact value does not matter as long as it is earlier than the earliest
event and produces valid unix-epoch seconds.

**Monotonic base**: pick an arbitrary monotonic-nanosecond base for the
kernel clock (e.g. 5000000000000 — approximately 83 minutes of uptime in
nanoseconds). The first kernel event's raw timestamp is this base.

**Per-event timestamp computation**:

Given the run's `LOGGING_START` wall-clock time `W` and monotonic base `M`:

```
clock_offset = W - (M / 1e9)
```

For a desired wall-clock time `T` (unix epoch seconds) for an event:

```
kernel monotonic_ns = (T - clock_offset) * 1e9
postgres timestamp  = T
```

This ensures `load_master_log`'s calibration (`ts = raw_ns / 1e9 + clock_offset`)
recovers `T` exactly.

**Resolving wall-clock times from the spec**:

1. Parse `time_of_day` (scenario-level, `"HH:MM"`) as wall-clock on the
   generation date → this is `T_0`, the unix-epoch time of the first
   session's first event.

2. For sequential sessions (no `concurrent_with`): session N's first event
   starts at the previous session's last event's time + `delay_after_previous_seconds`.
   The first session starts at `T_0`.

3. For `concurrent_with: <label>`: resolve the referenced session's full
   schedule first. Then place this session's first event at a random point
   strictly between the referenced session's first and last event times.
   If the referenced session has only one event, place this session's first
   event at the same time as that event (degenerate case). If
   `concurrent_with` names a session that hasn't been resolved yet (e.g.
   forward reference or cycle), emit a hard error.

4. Within a session, consecutive events are separated by `step_gaps_seconds`,
   which cycles if shorter than `len(events) - 1`. The i-th event (0-indexed)
   has time = session_start + sum(step_gaps_seconds[j % len(step_gaps_seconds)]
   for j in range(i)).

5. Events implied by shell-parsing a `COPY ... TO PROGRAM` (see section 1.5)
   are inserted immediately after the SQL event that triggers them, each
   separated by a small fixed delta (0.001 seconds — close enough to fall
   within `SPAWN_WINDOW_SEC=5.0` for the first process, and within ppid
   lineage for subsequent processes).

**Tempo validation** (hard error on mismatch):

- `bursty`: every gap in `step_gaps_seconds` must be < 2.0 seconds.
- `steady`: every gap must be within 20% of the mean of all gaps.
- `off_hours`: the session's resolved first-event wall-clock time must
  fall outside 08:00–18:00 local time on the generation date.
- `scheduled`: no validation (per scenario_spec.md).

### 1.5 Shell parsing of COPY ... TO PROGRAM

When `sqlfacts.extract_query_facts` returns `is_program: True` and
`shell_cmd` is non-null, codegen must shell-parse `shell_cmd` to derive
the implied kernel events.

**Scope for v1**:

- Simple commands: `curl -sX POST https://... -d @-` → one `execve` event
  with `comm` = first word, `arg` = the full command string.
- Pipes: `cmd1 | cmd2 | cmd3` → one `execve` per pipeline segment, chained
  by ppid (cmd1's pid is ppid of cmd2, etc.).
- Output redirection: `cmd > /path/to/file` and `cmd >> /path/to/file` →
  one `execve` for the command + one `openat` file event for the path.
- Input redirection: `cmd < /path/to/file` → same pattern (execve + openat).

**Out of scope for v1** (hard error if encountered):

- Subshells: `$(...)`, backticks
- Background: `&`
- Semicolon chaining: `cmd1 ; cmd2` (use separate events instead)
- Shell builtins that aren't real executables
- Variable expansion: `$VAR`
- Here-documents, here-strings
- Process substitution: `<(...)`, `>(...)`

**Parsing approach**: use Python's `shlex.split()` on the shell_cmd string.
For pipes, split on `|` first (before shlex), then shlex-parse each segment.
For redirections, detect `>`, `>>`, `<` tokens in the shlex output and
extract the file path.

**connects_to derivation**: if the command is `curl` (or `wget`, `nc`,
`ncat`) and the event has an explicit `connects_to` field, use that. If
no `connects_to` is present, codegen does NOT attempt to parse URLs or
hostnames from the command arguments — the spec must provide `connects_to`
explicitly for any connection that matters. If neither is present, no
`connect` kernel event is emitted for this command.

### 1.6 Event-to-kernel-record mapping

Each spec event becomes one or more records in `kernel_events.json` and/or
`postgres_events.json`. The mapping:

**`sql` event** → one record in `postgres_events.json`:
```json
{
  "session_id": <session's backend_pid>,
  "session_start_time": <session's first-event timestamp, integer>,
  "backend_pid": <session's backend_pid>,
  "timestamp": <wall-clock unix epoch seconds>,
  "event_type": "ProcessUtility",
  "query": "<the literal SQL string>",
  "database": "casce_synthetic",
  "username": "<session's role>",
  "client_addr": "192.168.1.200",
  "client_port": "<session's backend_pid>"
}
```

Notes:
- `session_id` = `backend_pid` for synthetic data (Algorithm 1 uses
  `event.raw.get("session_id", event.pid)`, and both are the backend_pid).
- `event_type` is always `"ProcessUtility"` for codegen output. Algorithm 2
  does not branch on `event_type` — it reads `query` via `sqlfacts`.
- `database` is a fixed synthetic value. It is not used by any algorithm.
- `client_addr` and `client_port` are cosmetic; Algorithm 1/2 do not use them.
  Use fixed values.
- `username` should be set to the session's `role` field from the spec.
  If the session has no `role`, use `"postgres"`.

If this SQL event triggers shell-parse-implied events (section 1.5), those
are emitted as kernel records immediately after this postgres record in
timestamp order.

**`sql` event for `anchor: synthetic` sessions**: codegen prepends one
invisible SQL event (`anchor_query`, default `"SELECT 1"`) before the
session's explicit events. This is a real postgres record — it is what
registers the backend_pid in Algorithm 1's `active_sessions`.

**`process` event** → one record in `kernel_events.json`:
```json
{
  "pid": <allocated pid>,
  "ppid": <parent's pid per section 1.3>,
  "uid": 0,
  "timestamp": <monotonic nanoseconds>,
  "comm": "<process.comm>",
  "syscall": "execve",
  "arg": "<full command: comm + space-joined args>"
}
```

**`file` event** → one record in `kernel_events.json`:
```json
{
  "pid": <parent process's pid>,
  "ppid": <parent process's ppid>,
  "uid": 0,
  "timestamp": <monotonic nanoseconds>,
  "comm": "<parent process's comm>",
  "syscall": "<file.syscall: openat | unlink | rename>",
  "arg": "<file.path>"
}
```

Note: `file` events reuse the parent process's pid/ppid/comm — they are
syscalls made by that process, not new processes. This matches how real
kernel tracing works (eBPF traces syscalls on a process).

**`connect` event** → one record in `kernel_events.json`:
```json
{
  "pid": <parent process's pid>,
  "ppid": <parent process's ppid>,
  "uid": 0,
  "timestamp": <monotonic nanoseconds>,
  "comm": "<parent process's comm>",
  "syscall": "connect",
  "arg": "",
  "dest_ip": "<connect.ip>",
  "dest_port": <connect.port>
}
```

**`connects_to` on a sql or process event**: if present, emit one additional
`connect` kernel record after the event's own record(s), using the parent
process's pid/ppid or (for sql events that spawned processes) the last
spawned process's pid/ppid.

### 1.7 Output files

All written to `<run_dir>/`:

#### 1.7.1 postgres_events.json

JSON-lines (one JSON object per line). First line is the LOGGING_START
marker:

```json
{"marker": "LOGGING_START", "timestamp": <wall-clock unix epoch float>}
```

Subsequent lines are postgres event records in timestamp order across all
sessions in the run.

#### 1.7.2 kernel_events.json

JSON-lines. First line is the same LOGGING_START marker (same timestamp
value):

```json
{"marker": "LOGGING_START", "timestamp": <wall-clock unix epoch float>}
```

Subsequent lines are kernel event records in monotonic-timestamp order
across all sessions in the run.

#### 1.7.3 labels.csv

CSV with columns `session_id,label`. One row per session (across all
scenarios). `session_id` = the session's backend_pid. `label` = the
session's effective class (`session.class` if set, else
`scenario.default_class`), title-cased and with underscores converted to
spaces for readability (e.g. `"Malicious"`, `"Benign"`).

`anchor: none` sessions are included in labels.csv (they are real sessions
with a label — they just won't correlate in Algorithm 1). Include one
leading row with empty `session_id` and label `"Normal"` to match the
existing dataset format (this row is a header artifact the real datasets
have — Algorithm 2 ignores rows with empty session_id).

#### 1.7.4 expectation_manifest.json

A single JSON file (not JSON-lines) containing the expectation manifest
that `validate_run.py` checks against. Schema:

```json
{
  "run_dir": "<run_dir>",
  "generation_date": "YYYY-MM-DD",
  "logging_start_timestamp": <float>,
  "scenarios": {
    "<scenario_id>": {
      "source_file": "<filename.yaml>",
      "family_id": "<family_id>",
      "matched_pair_id": "<matched_pair_id or null>",
      "matched_dimensions": {"fixed": [...], "varied": [...]} | null,
      "default_class": "<benign|malicious>",
      "rule_engine_relationship": "<value>",
      "sessions": {
        "<session_label>": {
          "backend_pid": <int>,
          "class": "<effective class>",
          "role": "<role or null>",
          "anchor": "<db|synthetic|none>",
          "expected_correlation": <true|false>,
          "expected_nodes": [
            {
              "node_type": "<Session|Query|Table|Process|File|Endpoint|Role>",
              "key_hint": "<what NODE_KEY would return, stringified>",
              "source_step_id": "<step_id or null>",
              "source_event_type": "<sql|process|file|connect|implied>"
            }
          ],
          "expected_edges": [
            {
              "edge_type": "<executes|accesses|backed_by|spawns|opens|connects_to>",
              "source_node_type": "<type>",
              "target_node_type": "<type>",
              "source_step_id": "<step_id or null>",
              "target_step_id": "<step_id or null>"
            }
          ]
        }
      }
    }
  }
}
```

**Derivation rules for expected_nodes and expected_edges**: codegen
computes these by running the same `identify_node_types` and
`find_connection_rule` logic from `algorithm2.py` conceptually — it
knows exactly what events it emitted and what `sqlfacts` returns for each
SQL string (it already called `sqlfacts.extract_query_facts` to validate
the SQL). The manifest records the expected graph topology so validate_run
can compare without re-deriving from the spec.

Key fields:
- `expected_correlation`: `True` for `anchor: db` and `anchor: synthetic`,
  `False` for `anchor: none`.
- `key_hint`: a human-readable string representation of what
  `NODE_KEY[node_type](attrs)` would return. For Process nodes this is the
  pid; for Table nodes, the table_name; for Endpoint nodes,
  `"(ip, port)"`. Used for matching against the actual graph.

### 1.8 Ordering

Records within each output file are sorted by timestamp (wall-clock for
postgres, monotonic-ns for kernel). When two records have the same
timestamp, postgres records for a session come before kernel records for
that session (to ensure Algorithm 1 registers the session before the
kernel events that depend on it arrive).

### 1.9 Error handling

**Hard build errors** (exit immediately, no output files written):

- YAML parse failure on any spec file.
- Schema validation failure (against `scenario_spec.schema.json`).
- `sqlfacts.extract_query_facts` returns `parse_error` for any `sql` event.
- A `parent` step_id reference that does not resolve to a prior step in
  the same session.
- A `concurrent_with` reference that does not resolve to another session
  label in the same scenario, or creates a cycle.
- A `matched_pair_id` in a spec whose sibling is not present in another
  spec file in the same `<run_dir>/specs/` directory.
- A `matched_dimensions` entry not in the closed vocabulary.
- A `COPY ... TO PROGRAM` shell string that uses constructs outside v1
  scope (section 1.5).
- An `anchor: db` session with zero `sql` events.
- A `tempo`/`step_gaps_seconds` mismatch (section 1.4).
- A process tree that exceeds D_MAX=8 depth from backend_pid.
- Duplicate `scenario_id` across spec files in the same run.
- Duplicate `session_label` within a scenario.
- Duplicate `step_id` within a session.
- A scenario in which no session contains a `process`/`file`/`connect`
  event, and no `sql` event is a `COPY ... TO PROGRAM` that implies one —
  i.e. no session anywhere in the scenario carries real OS-layer
  activity. This is the cross-layer scope invariant from
  `scenario_spec.md` ("at least one session in the scenario must carry
  real OS-layer activity"); it is a build error here, not merely
  documented as codegen's responsibility and left unenforced.
- An event with no `sql`/`process`/`file`/`connect` key (or more than one).
- A `file` or `connect` event with no `parent`.

**Not errors** (proceed normally):

- A `process` event with no `parent` (ppid defaults to backend_pid).
- A session with no `timing` block (use default gaps of 1.0 seconds, no
  tempo validation).
- A scenario with no `time_of_day` (use `"00:00"` — midnight).
- A scenario with no `default_class` (every session must then have an
  explicit `class`, or that is a hard error).
- Missing `role` on a session (default to `"postgres"`).

### 1.10 Exit codes and output contract

| Exit code | Meaning |
|-----------|---------|
| 0 | All specs processed, all output files written. |
| 1 | Hard build error. stderr contains a human-readable message identifying the failing spec file, the failing element (scenario/session/event), and the reason. No output files are written (if any were partially written, delete them). |

**stdout**: on success, one line:
```
OK: <N> scenarios, <M> sessions, <P> events → <run_dir>
```

**stderr**: on failure, one or more lines:
```
ERROR: <spec_filename>: <scenario_id>/<session_label>/<step_id>: <reason>
```

codegen does NOT write partial output on error — either all files are
written or none are. This lets a calling agent treat exit-code-0 as
"the run directory is ready for validate_run.py" without checking file
existence.

---

## 2. validate_run.py

### 2.1 Invocation

```
python datagen/validate_run.py <run_dir>
```

`<run_dir>` must already contain the files codegen wrote: `postgres_events.json`,
`kernel_events.json`, `labels.csv`, `expectation_manifest.json`, and
`specs/*.yaml`.

### 2.2 Validation sequence

Four checks, run in order. A failure in an earlier check does not prevent
later checks from running — all checks execute, and all failures are
collected and reported together.

#### Check 1: Schema and enum conformance

Re-parse every `<run_dir>/specs/*.yaml` against `scenario_spec.schema.json`.
Verify:
- All required fields present.
- `matched_dimensions` entries are in the closed vocabulary
  (`process_tree_shape`, `syscall_sequence`, `timing_pattern`,
  `sql_content`, `connects_to_destination`, `role`).
- Every `anchor: db` session has at least one `sql` event.
- `tempo`/`step_gaps_seconds` consistency (same rules as codegen section 1.4).
- Every event has exactly one of `sql`/`process`/`file`/`connect`.
- Every `file` and `connect` event has a `parent` field.
- Every `parent` reference resolves to a `step_id` in the same session.
- At least one session in the scenario carries real OS-layer activity
  (the cross-layer scope invariant; see codegen section 1.9).

This check is redundant with codegen's own validation (codegen refuses to
produce output for an invalid spec), but running it in the validator too
catches the case where someone hand-edited a spec after codegen ran, or
codegen has a bug in its own validation.

#### Check 2: pglast parse check

For every `sql` event in every spec, call `sqlfacts.extract_query_facts(sql_string)`.
A result containing `parse_error` is a failure. Report the scenario_id,
session_label, step_id (if any), and the parse error message.

#### Check 3: Pipeline correlation and graph-shape check

This is the core validation. Run the real pipeline against the generated
data and compare the result to codegen's expectation manifest.

**Step 3a — Run Algorithm 1:**

```python
from algorithm_1 import run_one
master_log, correlated = run_one(Path(run_dir))
```

This reads `postgres_events.json` and `kernel_events.json`, calibrates
the clock, and returns the master log and all correlated
`(session_key, event_id)` pairs.

**Step 3b — Build the event table and correlation CSV that Algorithm 2 expects:**

Algorithm 2's `run()` function takes file paths (`event_table_path`,
`correlation_path`), not in-memory data. validate_run must write
Algorithm 1's output to temporary files in the format Algorithm 2 expects:

- `event_table.json`: a JSON array of objects, one per event that was
  correlated:
  ```json
  [
    {
      "event_id": <int>,
      "source": "<kernel|postgres>",
      "timestamp": <float, unix epoch seconds>,
      "pid": <int>,
      "raw": { <original record dict> }
    }
  ]
  ```
  Sorted by event_id.

- `correlation.csv`: CSV with columns `session_key,event_id`, one row per
  correlated pair.

Write these to a temporary directory (e.g. `<run_dir>/tmp_validate/`),
cleaned up after validation completes.

**Step 3c — Run Algorithm 2:**

```python
from algorithm2 import run as run_alg2

active_graphs, manifest_rows, orphans, parse_errors = run_alg2(
    event_table_path=tmp_dir / "event_table.json",
    correlation_path=tmp_dir / "correlation.csv",
    out_dir=tmp_dir / "graphs",
    run_id="validate",
    labels_path=Path(run_dir) / "labels.csv",
)
```

**Step 3d — Compare against expectation manifest:**

Load `<run_dir>/expectation_manifest.json`. For each scenario's each
session:

1. **Correlation check**: if `expected_correlation` is `True`, verify that
   the session's backend_pid appears as a `session_key` in Algorithm 1's
   correlated output. If `expected_correlation` is `False` (anchor: none),
   verify it does NOT appear.

2. **Node-type check**: for each entry in `expected_nodes`, verify that a
   node of the specified `node_type` exists in the session's graph
   (`active_graphs[backend_pid]`). Match by node type and `key_hint`
   where possible (e.g. for Process nodes, check that a
   `("Process", <pid>)` node exists).

3. **Edge-type check**: for each entry in `expected_edges`, verify that at
   least one edge of the specified `edge_type` exists between nodes of the
   specified `source_node_type` and `target_node_type` in the session's
   graph. The check is structural (type-to-type with the right edge label),
   not identity-exact (specific node ids may differ due to event_id
   assignment).

4. **No-extra-sessions check**: verify that the set of session_keys that
   Algorithm 1 resolved matches exactly the set of backend_pids with
   `expected_correlation: True` in the manifest. An unexpected extra
   session is a failure (indicates a pid collision or rogue event).

**Algorithm 3 scope note**: this check does NOT run
`algorithm_3_abstract.abstract_session_graph()`. Algorithm 3 currently has
`relation`/`rel` key mismatch and missing `label` attribute bugs that make
it emit zero Behavior nodes. Once those are fixed on their own track,
extend Step 3c to call Algorithm 3 and extend the expectation manifest to
include expected Behavior nodes. The extension point is here — add a
Step 3e that calls Algorithm 3 and checks a `expected_behavior_nodes`
field in the manifest, gated on a `--check-alg3` flag or a manifest version
field.

#### Check 4: Matched-pair check

For every scenario that has a `matched_pair_id`:

1. **Sibling existence**: verify that exactly one other scenario in
   `<run_dir>/specs/` shares the same `matched_pair_id`. If zero or more
   than one sibling exists, that is a failure.

2. **Opposite class**: checked per corresponding session pair (same
   correspondence-by-position rule as the fixed/varied checks below), not
   at scenario level. Each corresponding session pair's effective class
   (`session.class` if set, else `scenario.default_class`) must be
   opposite. A scenario-level `default_class` comparison would let a pair
   validate without any of their actual sessions differing in class —
   vacuous in exactly the way B1 (matched-dimensions vocabulary) was
   fixed to prevent for the dimension checks themselves. Any corresponding
   pair whose sessions are NOT opposite is a failure.

3. **Fixed-dimension checks**: for each dimension in `matched_dimensions.fixed`,
   verify the pair satisfies the "fixed means" column:

   | Dimension | Check |
   |-----------|-------|
   | `process_tree_shape` | Both halves' process trees have the same topology: same sequence of `comm` values at each tree position, same parent-child edges (ignoring pid values and literal `args` content). Build a canonical tree from each half's events (process events + shell-implied processes), compare the trees structurally. |
   | `syscall_sequence` | Extract the ordered list of syscalls implied by each half's events (execve, openat, unlink, rename, connect — in event-list order, including implied events from shell parsing). The two lists must be identical. |
   | `timing_pattern` | Corresponding sessions must have the same `tempo` value. Each corresponding `step_gaps_seconds` entry (cycling if lengths differ) must be within 20% of the other half's value. "Corresponding sessions" are matched by position in the `sessions` list. |
   | `sql_content` | Corresponding `sql` events (by position within their respective sessions) must be byte-identical. |
   | `connects_to_destination` | Every resolved `{ip, port}` in one half (from explicit `connects_to` fields and from `connect` events) must equal the corresponding `{ip, port}` in the other half, matched by event position within corresponding sessions. |
   | `role` | Corresponding sessions must have identical `role` values. |

4. **Varied-dimension checks**: for each dimension in `matched_dimensions.varied`,
   verify the pair satisfies the "varied means" column:

   | Dimension | Check |
   |-----------|-------|
   | `process_tree_shape` | The canonical trees differ in at least one edge or node (at least one `comm` differs, or the topology differs). |
   | `syscall_sequence` | At least one syscall differs or the order differs. |
   | `timing_pattern` | `tempo` differs on at least one corresponding session, OR at least one corresponding gap differs by more than 20%. |
   | `sql_content` | Not byte-identical on at least one corresponding event, AND the difference is not merely a literal swap inside an otherwise-identical query — the table, column, or verb referenced must actually differ. (Implementation note: pglast-parse both SQL strings; compare the AST structure after stripping literal values. If the ASTs are structurally identical, the difference is only literals and does NOT satisfy "varied." If the ASTs differ structurally, it does.) |
   | `connects_to_destination` | At least one resolved `{ip, port}` differs. |
   | `role` | At least one corresponding session has a different `role`. |

### 2.3 Output format

validate_run produces two outputs:

**Exit code**:

| Exit code | Meaning |
|-----------|---------|
| 0 | All checks passed for all scenarios/sessions. |
| 1 | One or more checks failed. |
| 2 | validate_run itself hit an internal error (e.g. missing files, import failure). |

**Failure report**: written to both stderr and to
`<run_dir>/validation_report.json`. The JSON structure:

```json
{
  "run_dir": "<run_dir>",
  "timestamp": "ISO-8601",
  "overall": "pass" | "fail",
  "checks": {
    "schema": {
      "status": "pass" | "fail",
      "failures": [
        {
          "scenario_id": "...",
          "session_label": "..." | null,
          "step_id": "..." | null,
          "reason": "..."
        }
      ]
    },
    "pglast": {
      "status": "pass" | "fail",
      "failures": [...]
    },
    "pipeline": {
      "status": "pass" | "fail",
      "algorithm_3_checked": false,
      "failures": [
        {
          "scenario_id": "...",
          "session_label": "...",
          "check_type": "correlation" | "node_type" | "edge_type" | "extra_session",
          "expected": "...",
          "actual": "...",
          "reason": "..."
        }
      ]
    },
    "matched_pairs": {
      "status": "pass" | "fail",
      "failures": [
        {
          "matched_pair_id": "...",
          "scenario_id": "...",
          "check_type": "sibling_missing" | "same_class" | "fixed_mismatch" | "varied_not_different",
          "dimension": "..." | null,
          "reason": "..."
        }
      ]
    }
  },
  "summary": {
    "scenarios_checked": <int>,
    "sessions_checked": <int>,
    "pairs_checked": <int>,
    "total_failures": <int>
  }
}
```

**stderr output** (for calling agents that read stderr directly):
one line per failure in the format:
```
FAIL [<check_name>] <scenario_id>/<session_label>: <reason>
```
followed by a summary line:
```
VALIDATION FAILED: <N> failures across <M> scenarios
```
or on success:
```
VALIDATION PASSED: <N> scenarios, <M> sessions, <P> pairs checked
```

### 2.4 Temporary files

validate_run writes Algorithm 1's output to `<run_dir>/tmp_validate/` and
Algorithm 2's graph output to `<run_dir>/tmp_validate/graphs/`. These are
deleted on exit regardless of pass/fail (use a try/finally or atexit handler).
If `<run_dir>/tmp_validate/` already exists at startup, delete it first.

---

## 3. Open questions

These are places where `scenario_spec.md` or the pipeline source left
something genuinely underspecified. Each needs a decision before
implementation — the spec author (or the advisor) should resolve them,
not the implementer.

### 3.1 Multi-session matched-pair correspondence

The matched-pair dimension checks compare "corresponding sessions" and
"corresponding events." scenario_spec.md does not define what
"corresponding" means when two paired scenarios have different numbers of
sessions or different numbers of events per session.

**This spec assumes**: correspondence is by position in the `sessions`
list (session 0 ↔ session 0, session 1 ↔ session 1, etc.). If the two
halves have different numbers of sessions, the extra sessions in the
longer half have no correspondent — `fixed` dimension checks skip them,
`varied` dimension checks count them as automatically satisfied (the
structure differs). Same rule for events within corresponding sessions.

**If this is wrong**, the matched-pair checks in section 2.2 Check 4
need a different correspondence rule (by `session_label` match, by
`role` match, etc.).

### 3.2 Scenario-level vs. session-level class for matched-pair opposition — resolved

Originally assumed scenario-level `default_class` comparison. Fixed: use
per-session correspondence instead (Check 4, point 2) — the same
correspondence rule already used for the fixed/varied dimension checks.
A scenario-level check would validate a pair without requiring any of
their actual sessions to differ in class, which is a vacuous check of
the same kind B1 closed for the dimension vocabulary.

### 3.3 `uid` field in generated kernel events

The existing kernel data uses `uid: 0` for postgres-related processes and
`uid: 1000` for user-space processes. Neither Algorithm 1 nor Algorithm 2
reads `uid`. This spec uses `uid: 0` for all generated events. If uid
becomes significant later, codegen will need a mapping from scenario
roles to uids.

### 3.4 `event_type` for SQL events

The real postgres log has multiple event types (`ExecutorStart`,
`ExecutorEnd`, `ProcessUtility`). Algorithm 2 does not branch on
`event_type`. This spec emits all SQL events as `ProcessUtility`. If
Algorithm 2 later uses `event_type`, codegen will need a mapping (e.g.
SELECT/INSERT/UPDATE/DELETE → ExecutorStart+ExecutorEnd pairs,
DDL/COPY → ProcessUtility).

### 3.5 `session_start_time` precision

The real postgres data uses integer `session_start_time` (truncated unix
epoch). This spec follows that convention (integer, not float). If
Algorithm 1 ever uses sub-second precision on `session_start_time`, this
needs revisiting.

### 3.6 Cross-layer scope enforcement — resolved

Originally left unenforced in both scripts. Fixed: it is now a codegen
hard build error (section 1.9) — a scenario with no OS-layer session
anywhere never produces output at all, rather than silently shipping.
validate_run's schema check (Check 1) additionally re-checks it for the
same reason it re-checks the other invariants codegen already enforces:
catching a spec hand-edited after codegen ran.
