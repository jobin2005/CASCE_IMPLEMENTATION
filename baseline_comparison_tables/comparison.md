# Baseline comparison — full results (multi-domain corpus, family-disjoint split)

Every number below is read directly from its own result JSON (see `baseline_comparison_tables/build_comparison.py`) -- nothing here is hand-transcribed or re-derived.

| Model | Category | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | Params |
|---|---|---|---|---|---|---|---|---|
| Logistic Regression | Classical ML | 0.7046 | 0.6208 | 0.9630 | 0.7550 | 0.5270 | 0.7992 | — |
| Random Forest | Classical ML | 0.7340 | 0.6496 | 0.9493 | 0.7713 | 0.4588 | 0.8519 | — |
| MLP | Classical ML | 0.7171 | 0.6348 | 0.9451 | 0.7594 | 0.4872 | 0.8448 | — |
| XGBoost | Classical ML | 0.7340 | 0.6496 | 0.9493 | 0.7713 | 0.4588 | 0.8524 | — |
| GCN (via GraphConv) | GNN (same repr.) | 0.9596 | 0.9455 | 0.9704 | 0.9578 | 0.0501 | 0.9963 | 1,995,329 |
| GraphSAGE | GNN (same repr.) | 0.9591 | 0.9355 | 0.9810 | 0.9577 | 0.0605 | 0.9960 | 1,995,329 |
| GAT | GNN (same repr.) | 0.9556 | 0.9316 | 0.9778 | 0.9541 | 0.0643 | 0.9959 | 2,020,929 |
| GATv2 | GNN (same repr.) | 0.9546 | 0.9515 | 0.9525 | 0.9520 | 0.0435 | 0.9948 | 2,033,729 |
| ShadeWatcher (TransR) | Provenance | 0.5923 | 0.5368 | 1.0000 | 0.6986 | 0.7729 | 0.6113 | — |
| MAGIC | Provenance | 0.6118 | 0.9246 | 0.1943 | 0.3211 | 0.0142 | 0.6728 | — |
| StreamSpot | Provenance | 0.4860 | 0.4710 | 0.7117 | 0.5669 | 0.7162 | 0.5976 | — |
| RT-APT | Provenance | 0.4726 | 0.4726 | 1.0000 | 0.6418 | 1.0000 | 0.5613 | — |
| Kairos (TGN) | Provenance | 0.4726 | 0.4725 | 0.9968 | 0.6411 | 0.9972 | 0.5207 | — |
| Unicorn (HistoSketch) | Provenance | 0.4726 | 0.4726 | 1.0000 | 0.6418 | 1.0000 | 0.4996 | — |
| FLASH | Provenance | 0.5344 | 1.0000 | 0.0148 | 0.0291 | 0.0000 | 0.5074 | — |
| CASCE (HeteroGATv2, full fused pipeline) | CASCE (reference) | 0.9511 | 0.9426 | 0.9546 | 0.9486 | 0.0520 | — | 2,033,729 |

CGL-AD is not included above — cite-only, no public implementation, see `provenance_baseline_results/cgl_ad_citation.md`. OmegaLog is not included — not a classifier, see `omegalog_comparison/omegalog_vs_casce.md` for the methodology comparison.