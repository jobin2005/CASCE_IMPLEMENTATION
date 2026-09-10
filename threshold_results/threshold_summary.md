# Threshold Sensitivity Analysis & Freezing Protocol

Following rigorous scientific evaluation methodology, alert threshold $\theta_A$ and response threshold $\theta_R$ were tuned and selected strictly on the validation set, frozen, and subsequently verified against the held-out test set.

- **Optimal Alert Threshold ($\theta_A$)**: `0.10` (maximizes validation F1 balancing precision and recall)
- **Optimal Response Threshold ($\theta_R$)**: `0.10` (selected for near-zero false positive rate to prevent service disruption)

### Frozen Test Performance Table

| Threshold | Precision | Recall | F1-Score | FPR | Specificity | AUROC | AUPRC |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$\theta_A = 0.10$** | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 1.0000 | 0.7500 | 0.5200 |
