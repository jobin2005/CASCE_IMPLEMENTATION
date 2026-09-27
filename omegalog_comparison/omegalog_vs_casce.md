# OmegaLog vs. CASCE — methodology study and comparison

CASCE's base paper. This is a conceptual/methodological comparison, not a
reproduced baseline: OmegaLog is a graph-construction and forensic-
investigation system, not a classifier, so there is no "run OmegaLog on our
corpus and get a benign/malicious verdict" experiment to perform — its
output is a graph for a human analyst, not a label. Where numbers from
OmegaLog's own paper are cited below, they are marked as such and are not
comparable to CASCE's own measured numbers, same rule as every provenance
citation in this project.

## Citation

**OmegaLog: High-Fidelity Attack Investigation via Transparent Multi-layer
Log Analysis.** Wajih Ul Hassan, Mohammad Ali Noureddine, Pubali Datta, Adam
Bates. NDSS 2020.

## 1. Methodology study: what OmegaLog actually does

OmegaLog's central idea is **universal provenance**: a single causal graph
that fuses two layers which are normally analyzed separately —

1. **System-layer provenance** — the standard kernel-audit graph (processes,
   files, sockets, syscall-derived edges), the same kind of substrate CASCE
   builds from eBPF telemetry.
2. **Application-layer log semantics** — OmegaLog statically analyzes a
   program's *binary* to find its logging statements (e.g. a `printf`/log4j-
   style call) and infers, via control-flow analysis, what each such
   statement means about program state. At runtime, when that exact log
   line is emitted, OmegaLog "grafts" its inferred semantic meaning onto the
   matching point in the system-layer causal graph.

The result is one graph that has both the causal precision of kernel audit
data and the human-readable semantic context of application logs — aimed
squarely at **post-hoc attack investigation**: giving a human analyst a
graph small and meaningful enough to reconstruct "what happened" quickly.
The paper reports ~12% average runtime overhead for the log-interception
mechanism. OmegaLog includes **no automated classifier** — it does not
output a malicious/benign verdict; that judgment is left to a human analyst
or a separate downstream detector.

## 2. Conceptual comparison

| Dimension | OmegaLog | CASCE |
|---|---|---|
| **Goal** | Forensic attack *investigation* (produce a readable graph for a human) | Automated *detection* (produce a risk score/verdict) + evidence trail |
| **Layers fused** | System-layer (kernel audit) + application-layer (free-text logs, via static binary analysis) | System-layer (eBPF kernel telemetry) + PostgreSQL-layer (SQL AST facts, via `pglast` parsing) |
| **Semantic source** | Inferred meaning of arbitrary log-print statements, discovered via static control-flow analysis of the binary | Structured SQL AST facts (table/column/role accessed, statement type) extracted deterministically by parsing the query itself |
| **Generality vs. precision** | General — works on any binary that logs, regardless of app; but log coverage/quality varies per application and can be incomplete | Precise but domain-bound — deep, exact understanding of what a SQL statement does, but only for PostgreSQL; does not generalize to other application layers without a new parser |
| **Output artifact** | A universal provenance graph, for a human analyst | A typed heterogeneous graph, a MITRE-mapped behavior abstraction, a rule-engine verdict, and a GAT-based risk score |
| **Automated classification** | None | Yes — HeteroGATv2 + chain-rule engine, fused into a threshold-gated alert/response decision |
| **Scope of one graph** | Typically whole-host, whole-incident-timeframe provenance | Bounded per-session (Algorithm 1's PID-ancestry correlation window) |

## 3. Graph-size comparison

CASCE's own corpus (measured directly, 500-graph random sample from the
10,002-graph multi-domain corpus, `output/corpus_multidomain/graphml/`):

| | Mean | Median | Min | Max |
|---|---|---|---|---|
| Nodes/graph | 9.5 | 10 | 6 | 16 |
| Edges/graph | 11.6 | 11 | 4 | 24 |

These are small graphs by provenance-research standards (OmegaLog and most
DARPA-TC-style systems operate over whole-host graphs that run from
thousands to millions of nodes for a single scenario). This is not an
apples-to-apples "CASCE produces smaller graphs than OmegaLog" claim — it
reflects a different scoping decision, not a compression technique applied
to the same underlying data (see §5). OmegaLog's own paper reports its
universal provenance graphs are more concise than raw whole-host audit
graphs from the same incident, but the exact reduction figures are from
their own DARPA-style evaluation corpus and are not re-measured here; citing
them as our own would be exactly the kind of cross-corpus number-blending
this project has avoided elsewhere.

## 4. Semantic information comparison

OmegaLog's semantic signal is **incidental and log-format-dependent**: it
only knows what a developer happened to log, and only what static
control-flow analysis can infer about that log statement's meaning. This
generalizes across applications but is fundamentally best-effort — a
security-relevant action that isn't logged, or is logged ambiguously,
contributes little semantic value.

CASCE's semantic signal is **structural and guaranteed**: every SQL
statement that reaches PostgreSQL is parsed by `pglast` into an exact AST,
so table access, column access, role changes, and statement type
(SELECT/COPY/ALTER/DROP/…) are always available, not contingent on whether
a developer happened to log that action. The tradeoff is scope: this
guarantee holds only for the PostgreSQL layer, whereas OmegaLog's log-based
approach would in principle also pick up semantics from the application
code calling into Postgres, which CASCE's current design does not observe.

## 5. Attack-chain representation comparison

OmegaLog produces a single fused causal graph; identifying an "attack
chain" within it is left to the human analyst reading the graph — the
system does not itself label any subgraph as a named attack pattern.

CASCE makes the attack chain **explicit and machine-actionable**: Algorithm
3 abstracts raw graph structure into MITRE ATT&CK-mapped `Behavior` nodes
(`DATA_ACCESS`, `EXTERNAL_TRANSFER`, `ACCOUNT_MANIPULATION`, …) linked by
`precedes` edges, and Algorithm 4's chain-rule table matches specific
ordered/co-occurring sequences of these behaviors (e.g.
`DATA_ACCESS → DATA_PACKAGING → EXTERNAL_TRANSFER` = "Data exfiltration") to
produce a named scenario label and severity score automatically. This is a
genuine capability OmegaLog does not have — at the cost of only recognizing
attack patterns that match a template in Algorithm 3, whereas a human
reading an OmegaLog graph is not limited to a predefined pattern set.

## 6. Dependency / graph-reduction comparison

Both systems confront the same well-known problem in provenance research —
**dependency explosion**, where naively including every causal edge (e.g.
every process that touched a shared log file) creates enormous, mostly-
irrelevant graphs — but solve it in different ways:

- **OmegaLog's approach**: semantic pruning/annotation. Application-log
  semantics let it distinguish which causal edges through a shared resource
  (e.g. a log file touched by many processes) are actually meaningful,
  reducing dependency explosion by adding *understanding* of what happened
  at each point, not by discarding structure outright.
- **CASCE's approach**: scope reduction. Algorithm 1 (Session-Anchored
  Correlation) bounds every graph to one session's causal footprint via
  PID-ancestry tracing up to a fixed depth (`D_MAX=8`) — dependency
  explosion is avoided structurally, by never constructing a whole-host,
  whole-lifetime graph in the first place, rather than by pruning one after
  the fact. This is a large part of why CASCE's graphs (§3) are so much
  smaller than typical whole-host provenance graphs.

Neither approach is strictly better in isolation: OmegaLog's method
preserves whole-host context (useful for reconstructing multi-stage,
multi-host attacks that span sessions), while CASCE's per-session scoping
sacrifices that cross-session context in exchange for smaller, faster-to-
classify graphs suited to real-time per-session detection rather than
after-the-fact whole-incident forensics. This is a real, disclosed
limitation of CASCE's design worth stating explicitly: an attack that
unfolds *across* multiple sessions (e.g. reconnaissance in one session,
exploitation in a later one) would not be visible within any single
session-scoped graph the way it would in OmegaLog's universal provenance
graph.
