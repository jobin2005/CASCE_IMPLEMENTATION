# Literature → experiment mapping

Every technique/paper this baseline comparison touches, and exactly which
script and result file addresses it. Status is one of: **Reproduced** (real
implementation, run on CASCE's own multi-domain corpus, under the same
family-disjoint protocol as CASCE itself), **Cited** (paper's own reported
numbers documented, explicitly not blended into this project's results
table), or **N/A — not a classifier** (methodology comparison only).

## Classical ML

| Technique | Script | Result | Status |
|---|---|---|---|
| Logistic Regression | `baseline_models/classical_ml.py` | `classical_ml_results/logistic_regression.json` | Reproduced |
| Random Forest | `baseline_models/classical_ml.py` | `classical_ml_results/random_forest.json` | Reproduced |
| MLP | `baseline_models/classical_ml.py` | `classical_ml_results/mlp.json` | Reproduced |
| XGBoost | `baseline_models/classical_ml.py` | `classical_ml_results/xgboost.json` | Reproduced |

## GNN architectures (same CASCE graph representation, isolating architecture only)

| Architecture | Source | Script | Result | Status |
|---|---|---|---|---|
| GCN | Kipf & Welling, ICLR 2017 (via `GraphConv`, PyG's own documented substitute — `GCNConv` doesn't support heterogeneous/bipartite message passing) | `baseline_models/gnn_baselines.py` | `gnn_results/gcn.json` | Reproduced |
| GraphSAGE | Hamilton et al., NeurIPS 2017 | `baseline_models/gnn_baselines.py` | `gnn_results/sage.json` | Reproduced |
| GAT | Veličković et al., ICLR 2018 (static attention) | `baseline_models/gnn_baselines.py` | `gnn_results/gat.json` | Reproduced |
| GATv2 | Brody et al., ICLR 2022 (dynamic attention — the architecture CASCE's own HeteroGATv2 is built on) | `baseline_models/gnn_baselines.py` | `gnn_results/gatv2.json` | Reproduced |
| — leave-one-category-out OOD sweep, all 4 architectures + classical ML | this project's own protocol | `baseline_models/ood_sweep.py` | `gnn_results/ood_sweep/ood_reverse_shell.json` | Reproduced |

## Provenance-graph intrusion/anomaly detectors

| System | Citation | Script | Result | Status |
|---|---|---|---|---|
| MAGIC | Jia et al., USENIX Security 2023 | `provenance_baseline_results/run_magic.py` (vendored real model code) | `provenance_baseline_results/magic_results.json` | Reproduced |
| StreamSpot | Manzoor et al., KDD 2016 | `baseline_models/streamspot.py` | `provenance_baseline_results/streamspot_results.json` | Reproduced |
| FLASH | Rehman et al., IEEE S&P 2024 | `baseline_models/flash.py` | `provenance_baseline_results/flash_results.json` | Reproduced |
| RT-APT | Weng et al., J. Network and Computer Applications 2024 | `baseline_models/rtapt.py` | `provenance_baseline_results/rtapt_results.json` | Reproduced |
| Unicorn | Han et al., NDSS 2020 | `baseline_models/unicorn.py` | `provenance_baseline_results/unicorn_results.json` | Reproduced (core HistoSketch/CWS mechanism; upgraded from an initial cite-only assessment) |
| ShadeWatcher | Zeng et al., IEEE S&P (Oakland) 2022 | `baseline_models/shadewatcher.py` | `provenance_baseline_results/shadewatcher_results.json` | Reproduced (core TransR mechanism only, not the downstream GNN refinement or the C++ audit parser — disclosed in the script; upgraded from an initial cite-only assessment) |
| Kairos | IEEE S&P 2024 | `baseline_models/kairos.py` | `provenance_baseline_results/kairos_results.json` | Reproduced (core TGN memory mechanism, without their neighbor-sampling/attention embedding refinement step — the "TGN-mem" ablation variant; upgraded from an initial cite-only assessment) |
| CGL-AD | Expert Systems with Applications, 2024 | — | `provenance_baseline_results/cgl_ad_citation.md` | Cited only — no public implementation exists, and the method is architecturally a streaming/temporal-graph classifier incompatible with a static-session-graph adaptation without inventing an unspecified "streamify" step |

## Base paper

| Work | Citation | Deliverable | Status |
|---|---|---|---|
| OmegaLog | Hassan et al., NDSS 2020 | `omegalog_comparison/omegalog_vs_casce.md` | N/A — not a classifier (graph-construction/forensic-investigation tool); methodology + 6-dimension conceptual comparison only, no accuracy-style metric exists to reproduce |

## Consolidated deliverables

| Deliverable | File |
|---|---|
| Master comparison table (all classifiers, one table) | `baseline_comparison_tables/comparison.md` / `.json` |
| OOD sweep table | `baseline_comparison_tables/comparison_ood_reverse_shell.md` |
| F1 / ROC-AUC / IID-vs-OOD figures | `baseline_comparison_figures/*.png` |
| This mapping | `baseline_comparison_tables/literature_to_experiment_mapping.md` |

## Notes on scope decisions

- Every **Reproduced** result used the exact same family-disjoint train/val/test split (`output/corpus_multidomain/algo4_splits/`) as CASCE's own model, so the master comparison table is a genuine apples-to-apples comparison within this project.
- Three provenance systems (Unicorn, ShadeWatcher, Kairos) were *initially* assessed as cite-only due to their full systems' resource/infrastructure requirements (64GB RAM, 12-hour training, multi-repo orchestration — each verified against the actual repository, not assumed), then reconsidered and reproduced at the level of their *core algorithmic mechanism*, scaled to CASCE's much smaller graphs. This distinction (core mechanism vs. full system) is stated explicitly in each script's docstring, not glossed over.
- CGL-AD remains cite-only for a categorically different reason (no code, and a streaming-graph design that doesn't map onto a static-graph classification task without an invented adaptation) — not a resource-cost decision.
- No number from any **Cited** or **N/A** row appears in `comparison.md`'s table — cross-corpus/non-classifier numbers are documented in their own files, never blended into this project's own measured results.
