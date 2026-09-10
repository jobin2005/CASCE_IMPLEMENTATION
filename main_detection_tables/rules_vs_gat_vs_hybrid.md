# Rules vs. GAT vs. Hybrid Evaluation (Algorithm 4 Validation)

| Model | Precision | Recall | F1-Score | FPR | Specificity | AUROC | AUPRC | TP | TN | FP | FN |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rules Only** | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 1.0000 | 0.7500 | 0.5200 | 1 | 48 | 0 | 1 |
| **GAT Only** | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 1.0000 | 0.9062 | 0.5909 | 1 | 48 | 0 | 1 |
| **Hybrid (Rules + GAT)** | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 1.0000 | 0.7500 | 0.5200 | 1 | 48 | 0 | 1 |
