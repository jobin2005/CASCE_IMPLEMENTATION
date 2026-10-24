# CASCE Evaluation Report

## 4. Fusion evaluation & 5. Threshold sensitivity (Validation Results)
Optimized weights and thresholds on the validation set to ensure independent capabilities crossing the alert threshold:
- **W_RULE**: 0.20
- **W_GAT**: 0.50
- **THETA_A**: 0.20
- **THETA_R**: 0.40

## 1. Overall CASCE evaluation
| Metric | Value |
|---|---|
| Precision | 0.9011 |
| Recall | 0.8817 |
| F1 | 0.8913 |
| FPR | 0.0677 |
| FNR | 0.1183 |
| Specificity | 0.9323 |
| AUROC | 0.9854 |
| AUPRC | 0.9805 |
| TP | 82 |
| TN | 124 |
| FP | 9 |
| FN | 11 |

## 2. Rules vs GAT vs Hybrid
| Metric | Rules Only | GAT Only | Hybrid |
|---|---|---|---|
| Precision | 0.6915 | 0.8426 | 0.9011 |
| Recall | 0.6989 | 0.9785 | 0.8817 |
| F1 | 0.6952 | 0.9055 | 0.8913 |
| FPR | 0.2180 | 0.1278 | 0.0677 |
| FNR | 0.3011 | 0.0215 | 0.1183 |
| AUROC | 0.6861 | 0.9854 | 0.9854 |

## 3. Algorithm 3 ablation
| Metric | Raw/Factual graph | Behavior abstraction | Behavior abstraction + chaining |
|---|---|---|---|
| Precision | 1.0000 | 0.9302 | 0.9011 |
| Recall | 0.6667 | 0.8602 | 0.8817 |
| F1 | 0.8000 | 0.8939 | 0.8913 |
| FPR | 0.0000 | 0.0451 | 0.0677 |

