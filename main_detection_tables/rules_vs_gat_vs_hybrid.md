# Rules vs. GAT vs. Hybrid Evaluation (Algorithm 4 Validation)

| Model | Precision | Recall | F1-Score | FPR | Specificity | AUROC | AUPRC | TP | TN | FP | FN |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rules Only** | 0.8917 | 0.8743 | 0.8829 | 0.0763 | 0.9237 | 0.8917 | 0.8049 | 939 | 1380 | 114 | 135 |
| **GAT Only** | 1.0000 | 0.7477 | 0.8556 | 0.0000 | 1.0000 | 0.9625 | 0.9664 | 803 | 1494 | 0 | 271 |
| **Hybrid (Rules + GAT)** | 0.8944 | 0.8994 | 0.8969 | 0.0763 | 0.9237 | 0.9436 | 0.9367 | 966 | 1380 | 114 | 108 |
