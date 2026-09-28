# Kairos — superseded by a real implementation

**Status update: reconsidered.** The 64GB RAM requirement below applies to
Kairos's own whole-host, DARPA-scale deployment. CASCE's session graphs are
tiny (mean 9.5 nodes), so their core TGN mechanism was implemented directly
via `torch_geometric.nn.TGNMemory` (the exact class their own code imports)
at a scale that doesn't need anywhere near that much memory. See
`baseline_models/kairos.py` and `kairos_results.json`
(roc_auc=0.521, on CASCE's own corpus). The rest of this file documents the
original assessment, which still correctly describes why their *full*
pipeline (PostgreSQL ingestion + whole-host scale) wasn't attempted.

---

## Citation

**Kairos: Practical Intrusion Detection and Investigation using
Whole-system Provenance.** IEEE Symposium on Security and Privacy (S&P),
2024. [arXiv:2308.05034](https://arxiv.org/abs/2308.05034) ·
Code: [ubc-provenance/kairos](https://github.com/ubc-provenance/kairos)

## Method

A Temporal Graph Network (TGN) — a GNN encoder-decoder with a learned memory
module over a stream of timestamped edges — trained to predict each system
event's edge type; the prediction error at each edge is the anomaly score.
Detected anomalies are aggregated into a compact "attack summary graph" for
analyst investigation, which is Kairos's main contribution beyond raw
detection accuracy.

## Why not attempted, specifically

We checked the actual repository (not just the paper) before deciding this:
it includes a working `StreamSpot/` pipeline structurally similar to what we
built for our own StreamSpot/RT-APT baselines. Two concrete blockers, both
stated by Kairos's own documentation, not assumed by us:

1. **Memory**: their own `StreamSpot/src/README.md` states *"Make sure your
   machine has enough memory (at least 64GB)"* to run the StreamSpot
   experiments. This development machine has ~7.4GB of RAM total. This is a
   hard constraint, not a performance inconvenience.
2. **Infrastructure**: their pipeline ingests raw audit records into a
   PostgreSQL table (`raw_data`) with a specific schema as a preprocessing
   step, then trains a `TGNMemory`-based model reading pre-serialized
   `.TemporalData` tensor files keyed to their exact dataset's graph
   numbering (`graph_0.TemporalData`, `graph_100.TemporalData`, …) — adapting
   this to CASCE's static session-graph corpus would mean rebuilding their
   ingestion pipeline from scratch, on top of the memory constraint above.

## Reported results (as stated in the paper — not independently verified)

On the DARPA TC **CADETS** dataset, Kairos reports precision 0.64, recall
0.75, F1 0.69 (edge/event-level detection, not graph-level classification —
Kairos's whole design targets fine-grained event-level anomaly attribution,
not the graph-level benign/malicious classification every other baseline in
this project performs). These numbers are on DARPA TC data, not CASCE's
corpus, and are not comparable to this project's own measured results —
cited here only to document what Kairos claims on its own benchmark.
