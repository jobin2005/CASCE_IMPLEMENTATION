# Honest Evaluation: In-Distribution Re-Recognition vs. Zero-Day Generalization

| Metric | In-Distribution (`labels_test_indist.json`)<br>*(Re-recognition of Known Families)* | Held-Out Zero-Day (`labels_heldout_eval.json`)<br>*(True Generalization to Unseen Families)* | Impact / Delta ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **Total Test Sessions** | 1,878 (384 Malicious, 1,494 Normal) | 7,267 (2,480 Malicious, 4,787 Normal) | +5,389 sessions evaluated |
| **Precision** | **1.0000** (100.0%) | **1.0000** (100.0%) | **0.00%** (Zero false alarms preserved) |
| **Recall (TPR)** | **0.9974** (99.74%) | **0.5016** (50.16%) | -49.58% (Unseen payload gap) |
| **F1-Score** | **0.9987** | **0.6681** | -0.3306 |
| **False Positive Rate (FPR)**| **0.0000** (0.00%) | **0.0000** (0.00%) | **0.00%** (No false alarms) |
| **Specificity (TNR)** | **1.0000** (100.0%) | **1.0000** (100.0%) | **0.00%** |
| **False Negative Rate (FNR)**| **0.0026** (0.26%) | **0.4984** (49.84%) | +49.58% |
| **AUROC** | **0.9999** | **0.8725** | -0.1274 |
| **AUPRC (PR-AUC)** | **0.9997** | **0.8309** | -0.1688 |
| **True Positives (TP)** | 383 | 1,244 | 1,244 unseen attacks detected |
| **False Positives (FP)** | 0 | 0 | 0 false alarms across 4,787 normals |
| **False Negatives (FN)** | 1 | 1,236 | |
| **True Negatives (TN)** | 1,494 | 4,787 | |

### Scientific Significance & Interpretation for Paper Reviewers

1. **Why the 0.9987 number exists:**
   `labels_test_indist.json` evaluates sessions from attack families the model has been trained on. Because payloads and tool executions share identical signatures and graph shapes, the model achieves near-perfect re-recognition ($F_1 = 0.9987$, Recall $= 99.74\%$).

2. **Why the 0.6681 number is the honest zero-day metric:**
   `labels_heldout_eval.json` holds out entire attack families (e.g. `Data_Exfiltration`) completely from training and validation. The model has never seen these scripts, processes, or command sequences. 
   - Despite never having seen the attack payload, **CASCE detects 50.16% (1,244 / 2,480) of completely novel zero-day attack sessions** while maintaining **100% precision (0 false positives out of 4,787 benign sessions)**.
   - The AUROC of **0.8725** and AUPRC of **0.8309** demonstrate robust ranking capability even under zero-day conditions.
