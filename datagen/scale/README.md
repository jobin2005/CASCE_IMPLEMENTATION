# Template-driven scale generator (`datagen/scale/`)

Deterministically generates large volumes of CASCE scenario specs **without
near-duplicates**, for scaling the corpus toward the ~10k target. Emits spec
YAML only — the unchanged `datagen/codegen.py` + `datagen/validate_run.py`
remain the gate, and `datagen/gate_pilot.py` runs the corpus-level checks.

## Why templated, not hand-authored
Hand-authoring (or asking N LLM workers for "more scenarios") converges on a
few skeletons and produces near-duplicate families — invisible until a
family-level train/val/test split inflates validation scores. Instead a
scenario is treated as a point in a parameter space that a deterministic
generator samples, so volume comes from *covering* the space, not repeating
templates.

## How variation is produced
`domain × category × technique × role × structure × class × timing`, with
literals (attacker IPs, ports, endpoints, entity ids, names) drawn from large
**seeded** pools (`Pools`). Technique variants per category (e.g. exfil:
curl / gzip|curl / python-urllib / nc; priv-esc: suid-cp / setcap /
sudo-gtfobins / cron; revshell: bash / python / sh / perl; sqli: union /
boolean-blind / stacked / error-based) multiply the structural space well
past 10k before literals.

## How duplicates are prevented
1. **Full-content dedup** (`content_key`): a scenario whose literal content
   (role, SQL, processes, files, endpoints) matches one already emitted is
   rejected. Guarantees **0 exact duplicates**.
2. **Structural fingerprint cap** (`fingerprint`, `--fp-cap`): caps how many
   scenarios may share the same literal-stripped structure, so no skeleton
   dominates. (Matched pairs are exempt from the cap but not from content
   dedup.)
3. **Legitimacy by construction**: benign scenarios are only emitted for
   role/action/destination combinations that the domain model marks normal
   (ETL role does COPY-to-endpoint, the sensitive-read role audits PHI to an
   internal log, app roles do scoped DML). This keeps benign twins
   role-appropriate and puts every primitive (sensitive tables, UNION,
   INSERT/UPDATE, ordinary comms, internal+external endpoints) in **both**
   classes — closing the shortcuts the pilot gate found.
4. **Run-scoped ids**: `matched_pair_id`/`family_id`/`scenario_id` are
   prefixed by run, so pairs never collide across run directories.

## Anti-shortcut properties (500-scenario proof wave)
- 100% literal-unique content, 0 exact duplicates
- 0 node/edge presence×label shortcuts
- full-feature CV accuracy ~0.96 vs. node-presence 0.54 / graph-size 0.56 /
  bag-of-primitives 0.67 (rule-engine-relationship ~0.83 is annotation
  leakage, not a GAT input)
- verbs one-class only for genuine DDL (CREATE/TRUNCATE); UNION/INSERT/UPDATE
  in both classes
- matched pairs complete (0 incomplete), varied dimension rotated

## Usage
```bash
# generate specs
python datagen/scale/generate.py --target 10000 --out datagen/generated/gen --seed 1337

# per run dir: compile + validate (the gate)
for d in datagen/generated/gen/*/; do
  python datagen/codegen.py "$d" && python datagen/validate_run.py "$d"
done

# corpus-level shortcut gate
python datagen/gate_pilot.py --root datagen/generated/gen
```

## Tuning knobs
- `--target` total scenarios, split evenly across domains
- `--per-run` scenarios per run directory (family/pair confinement unit)
- `--fp-cap` max scenarios per structural fingerprint
- `--seed` changes every sampled literal reproducibly

## Scale-up notes (residuals to tune for the full 10k)
- Bias `build_sensitive_audit` to cover every sensitive table so none stays
  malicious-only in a given wave (a few sensitive tables can lean malicious
  at small N).
- Optionally add a malicious `openat` (dropper file write) so `openat` is not
  benign-only.
- `sql_content` is ~50% of matched-pair varied dimensions (copy-to-program +
  sqli both use it); rotate more if the varied-dimension check needs it.
