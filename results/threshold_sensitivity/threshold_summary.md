# Threshold Sensitivity Analysis & Freezing Protocol

Following rigorous scientific evaluation methodology, alert threshold $\theta_A$ and response threshold $\theta_R$ were tuned and selected strictly on the validation set, frozen, and subsequently verified against the held-out test set.

- **Optimal Alert Threshold ($\theta_A$)**: `0.10` (maximizes validation F1 balancing precision and recall)
- **Optimal Response Threshold ($\theta_R$)**: `0.65` (selected for near-zero false positive rate to prevent service disruption)

### Frozen Test Performance Table

| Threshold | Precision | Recall | F1-Score | FPR | Specificity | AUROC | AUPRC |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$\theta_A = 0.10$** | 0.8944 | 0.8994 | 0.8969 | 0.0763 | 0.9237 | 0.9436 | 0.9367 |
