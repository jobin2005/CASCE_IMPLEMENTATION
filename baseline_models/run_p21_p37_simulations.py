#!/usr/bin/env python3
"""Master Orchestrator: Executes simulations of the 4 literature baseline papers
(P22, P25, P26, P27) on the CASCE multi-domain benchmark dataset.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

OUT_DIR = REPO / "baseline_models"

def main():
    print("="*70)
    print("EXECUTING SIMULATIONS FOR 4 SPECIFIC LITERATURE PAPERS (P22, P25, P26, P27)")
    print("="*70)
    
    python_bin = sys.executable
    
    scripts = [
        ("P25 (Casmiry et al. Frontiers '25 - Chi2 ML)", "baseline_models/p25_chisq_sqli.py"),
        ("P26 (Liu & Dai IET '24 - Hybrid BERT-LSTM)", "baseline_models/p26_bert_lstm.py"),
        ("P22 (Shlezinger et al. arXiv '25 - DistilBERT SQL)", "baseline_models/p22_distilbert_sql.py"),
        ("P27 (Zhang et al. KDD '24 - Multivariate DB Log)", "baseline_models/p27_multivariate_kdd.py"),
    ]
    
    for title, script_path in scripts:
        print(f"\n---> Running: {title} ({script_path})")
        res = subprocess.run([python_bin, str(REPO / script_path)], capture_output=True, text=True)
        print(res.stdout)
        if res.returncode != 0:
            print(f"[ERR] Error executing {script_path}:\n{res.stderr}")
            
    print("\nSynthesizing Master Comparison Table...")
    
    p25_res = json.loads((OUT_DIR / "p25_chisq_results.json").read_text())
    p26_res = json.loads((OUT_DIR / "p26_bert_lstm_results.json").read_text())
    p22_res = json.loads((OUT_DIR / "p22_distilbert_results.json").read_text())
    p27_res = json.loads((OUT_DIR / "p27_multivariate_results.json").read_text())
    
    summary = {
        "P25_Casmiry2025_Chi2_RF": p25_res.get("RandomForest"),
        "P26_Liu2024_BERT_LSTM": p26_res,
        "P22_Shlezinger2025_DistilBERT_RF": p22_res.get("DistilBERT_RF"),
        "P27_Zhang2024_Multivariate_RF": p27_res.get("Multivariate_KDD_RF"),
    }
    
    master_file = OUT_DIR / "p21_p37_comparison.json"
    master_file.write_text(json.dumps(summary, indent=2, default=float))
    print(f"\n[SUCCESS] Master paper comparison saved to {master_file}")

if __name__ == "__main__":
    main()
