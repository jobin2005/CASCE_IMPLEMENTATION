# Leave-one-category-out OOD sweep — 'reverse_shell' held out entirely from training

Every session of the held-out category (both malicious AND benign instances of that technique) is removed from train/val entirely; test_iid is a normal held-out split from the REMAINING categories (the "easy" split), test_ood is every session of the held-out category (a technique genuinely never seen during training, in any form).

| Model | Category | IID Acc | IID F1 | OOD Acc | OOD F1 | OOD FPR | OOD FN | OOD ROC-AUC |
|---|---|---|---|---|---|---|---|---|
| logistic_regression | Classical ML | 0.7316 | 0.7657 | 0.6231 | 0.7264 | 0.7540 | 0/1379 | 0.6230 |
| random_forest | Classical ML | 0.7941 | 0.8056 | 0.4998 | 0.0000 | 0.0000 | 1379/1379 | 0.3770 |
| GCN | GNN (same repr.) | 0.9816 | 0.9800 | 0.4998 | 0.0000 | 0.0000 | 1379/1379 | 0.7201 |
| SAGE | GNN (same repr.) | 0.9752 | 0.9729 | 0.4998 | 0.0000 | 0.0000 | 1379/1379 | 0.7050 |
| GAT | GNN (same repr.) | 0.9678 | 0.9654 | 0.4998 | 0.0000 | 0.0000 | 1379/1379 | 0.6475 |
| GATV2 | GNN (same repr.) | 0.9761 | 0.9738 | 0.4998 | 0.0000 | 0.0000 | 1379/1379 | 0.7275 |

Note: this sweep covers classical ML + the 4 bare GNN architectures on identical features/split, isolating architecture choice. CASCE's full fused pipeline (rule engine + HeteroGATv2) was not separately re-run on this OOD split -- GATv2's row above is the architecture CASCE's own classifier uses, not the full fused system.