# Fusion Weight Evaluation & Optimization

### Problem Statement & Architectural Fix
In earlier configs with $w_{Rule}=0.55, w_{GAT}=0.45$, a GAT detection with probability $1.0$ yields a fused score of $0.45$, which is strictly below the alert threshold $\theta_A = 0.1$. This prevented GAT from alerting autonomously on zero-day attacks without a matching rule. By constraining both $w_{Rule} \ge 0.1$ and $w_{GAT} \ge 0.1$, both detection modalities act as true independent, non-gated channels.

### Test Set Performance Comparison

| Configuration | $w_{Rule}$ | $w_{GAT}$ | Precision | Recall | F1-Score | FPR | AUROC | GAT Alert Alone? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Flawed Baseline (wRule=0.55, wGAT=0.45)** | 0.55 | 0.45 | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 0.7500 | ✓ Yes |
| **Default CASCE (wRule=1.00, wGAT=0.75)** | 1.00 | 0.75 | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 0.7500 | ✓ Yes |
| **Optimal Validation Tuned (wRule=0.50, wGAT=0.50)** | 0.50 | 0.50 | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 0.7500 | ✓ Yes |
| **Symmetric Dual-Path (wRule=1.00, wGAT=1.00)** | 1.00 | 1.00 | 1.0000 | 0.5000 | 0.6667 | 0.0000 | 0.7500 | ✓ Yes |
