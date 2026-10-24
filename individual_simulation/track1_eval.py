import json
import csv
import math
import shutil
import tempfile
import sys
from pathlib import Path

# Add repo to sys.path
sys.path.insert(0, "/home/adithyan/Desktop/backup/CASCE_IMPLEMENTATION")

# Paths
BASE_DIR = Path("/home/adithyan/Desktop/backup/CASCE_IMPLEMENTATION")
CATEGORY_DIR = BASE_DIR / "individual_simulation" / "category_experiments"
INTERMIXED_JSON = BASE_DIR / "individual_simulation" / "intermixed_pgbench_experiment" / "intermixed_experiment_summary.json"

import algorithm_1
import algorithm2
import algorithm_3_abstract
import algorithm_4_hybrid

def wilson_interval(successes, total, confidence=0.95):
    """Computes Wilson score interval for a binomial proportion."""
    if total == 0:
        return 0.0, 0.0, 0.0
    p_hat = successes / total
    z = 1.96  # 95% confidence
    denominator = 1 + (z**2) / total
    center = (p_hat + (z**2) / (2 * total)) / denominator
    spread = (z * math.sqrt((p_hat * (1 - p_hat) / total) + (z**2) / (4 * total**2))) / denominator
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return p_hat, lower, upper

def extract_category_session_scores():
    model = algorithm_4_hybrid.load_model(str(BASE_DIR / "casce_gat_v3p_ens2.json"))
    templates = algorithm_3_abstract.initialize_templates()
    
    categories = [
        {"name": "Class 1: Privilege Abuse & Escalation", "folder": "class_1_privilege_abuse"},
        {"name": "Class 2: Data Exfiltration", "folder": "class_2_data_exfiltration"},
        {"name": "Class 3: SQL Injection & Sabotage", "folder": "class_3_sqli_sabotage"},
        {"name": "Class 4: Multi-Stage APT Scenarios", "folder": "class_4_multistage_apt"},
    ]
    
    all_cat_sessions = {}
    
    for cat in categories:
        cat_folder = CATEGORY_DIR / cat["folder"]
        labels_file = cat_folder / "session_labels.jsonl"
        session_labels = {}
        with open(labels_file) as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    session_labels[item["session_id"]] = item["label"]
                    
        master_log, correlated = algorithm_1.run_one(cat_folder)
        with tempfile.TemporaryDirectory() as tmpdirname:
            tmp_root = Path(tmpdirname)
            algorithm_1.save_run_output(cat["folder"], master_log, correlated, tmp_root)
            event_table_path = tmp_root / f"{cat['folder']}_event_table.json"
            correlation_path = tmp_root / f"{cat['folder']}_session_correlation.csv"
            alg2_out = tmp_root / "alg2"

            lbl_csv = tmp_root / "labels.csv"
            with open(lbl_csv, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["session_id", "label"])
                for sid, lbl in session_labels.items():
                    writer.writerow([sid, lbl])

            active_graphs, _, _, _ = algorithm2.run(
                event_table_path, correlation_path, alg2_out, cat["folder"], lbl_csv
            )

            cat_sessions = []
            for sid, G_raw in active_graphs.items():
                lbl = session_labels.get(sid, "unknown")
                is_attack = ("Malicious" in lbl)
                G_enriched, behaviors = algorithm_3_abstract.abstract_session_graph(G_raw, templates)
                
                # Run detection with theta=0.0 to inspect raw scores
                det = algorithm_4_hybrid.detect(G_enriched, model, session_id=sid, theta_a=0.55, theta_r=0.55)
                cat_sessions.append({
                    "session_id": sid,
                    "label": lbl,
                    "is_attack": is_attack,
                    "risk_score": det["risk"],
                    "rule_score": det["rule_score"],
                    "gat_score": det["gat_score"]
                })
            all_cat_sessions[cat["name"]] = cat_sessions
            
    return all_cat_sessions

def analyze_thresholds(sessions, thresholds):
    results = {}
    for th in thresholds:
        tp, fp, fn, tn = 0, 0, 0, 0
        for s in sessions:
            flagged = (s["risk_score"] >= th)
            if s["is_attack"]:
                if flagged:
                    tp += 1
                else:
                    fn += 1
            else:
                if flagged:
                    fp += 1
                else:
                    tn += 1
        pos = tp + fn
        neg = fp + tn
        rec = tp / pos if pos > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else None
        fpr = fp / neg if neg > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec is not None and (prec + rec) > 0) else 0.0
        results[th] = {
            "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "Recall": rec, "Precision": prec, "FPR": fpr, "F1": f1
        }
    return results

from sklearn.metrics import roc_auc_score, average_precision_score

def compute_auc_metrics(sessions):
    y_true = [1 if s["is_attack"] else 0 for s in sessions]
    y_scores = [s["risk_score"] for s in sessions]
    if len(set(y_true)) > 1:
        roc_auc = roc_auc_score(y_true, y_scores)
        pr_auc = average_precision_score(y_true, y_scores)
    else:
        roc_auc = 0.0
        pr_auc = 0.0
    return round(roc_auc, 4), round(pr_auc, 4)

def main():
    print("Extracting category sessions and raw scores...")
    cat_sessions = extract_category_session_scores()
    
    thresholds = [0.45, 0.50, 0.55, 0.60]
    
    print("\n" + "="*80)
    print("CATEGORY BREAKDOWN & SENSITIVITY ANALYSIS")
    print("="*80)
    
    all_directed_sessions = []
    output_data = {"categories": {}, "directed_total": {}, "intermixed": {}}
    
    for cat_name, sess_list in cat_sessions.items():
        all_directed_sessions.extend(sess_list)
        print(f"\n--- {cat_name} (Total: {len(sess_list)}) ---")
        benign_count = sum(1 for s in sess_list if not s["is_attack"])
        attack_count = sum(1 for s in sess_list if s["is_attack"])
        print(f"  Composition: {attack_count} Attacks, {benign_count} Benign")
        
        for s in sess_list:
            tag = "ATTACK" if s["is_attack"] else "BENIGN"
            print(f"  [{tag:6s}] Risk: {s['risk_score']:.4f} (GAT: {s['gat_score']:.4f}, Rule: {s['rule_score']:.4f}) | {s['label']}")
        
        sweep = analyze_thresholds(sess_list, thresholds)
        roc_auc, pr_auc = compute_auc_metrics(sess_list)
        print(f"  ROC-AUC: {roc_auc:.4f}, PR-AUC: {pr_auc:.4f}")
        
        print("  Threshold Sweep:")
        for th, m in sweep.items():
            prec_str = f"{m['Precision']*100:.1f}%" if m['Precision'] is not None else "N/A"
            print(f"    theta={th:.2f} | TP={m['TP']}, FN={m['FN']}, FP={m['FP']}, TN={m['TN']} | Rec={m['Recall']*100:.1f}%, Prec={prec_str}, FPR={m['FPR']*100:.1f}%, F1={m['F1']:.4f}")
            
        output_data["categories"][cat_name] = {
            "sessions": sess_list,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "sweep": sweep
        }
            
    print("\n" + "="*80)
    print("TOTAL DIRECTED TESTBED SENSITIVITY SWEEP (53 sessions: 29 Attacks, 24 Benign)")
    print("="*80)
    total_sweep = analyze_thresholds(all_directed_sessions, thresholds)
    dir_roc_auc, dir_pr_auc = compute_auc_metrics(all_directed_sessions)
    print(f"Directed Testbed ROC-AUC: {dir_roc_auc:.4f}, PR-AUC: {dir_pr_auc:.4f}")
    
    for th, m in total_sweep.items():
        prec_str = f"{m['Precision']*100:.1f}%" if m['Precision'] is not None else "N/A"
        print(f"  theta={th:.2f} | TP={m['TP']}/{m['TP']+m['FN']}, FP={m['FP']}/{m['FP']+m['TN']} | Rec={m['Recall']*100:.1f}%, Prec={prec_str}, FPR={m['FPR']*100:.1f}%, F1={m['F1']:.4f}")

    print("\n" + "="*80)
    print("CONFIDENCE INTERVALS AT DEFAULT THETA = 0.55")
    print("="*80)
    for cat_name, sess_list in cat_sessions.items():
        m = analyze_thresholds(sess_list, [0.55])[0.55]
        rec_hat, rec_low, rec_high = wilson_interval(m["TP"], m["TP"] + m["FN"])
        fpr_hat, fpr_low, fpr_high = wilson_interval(m["FP"], m["FP"] + m["TN"])
        prec_tuple = wilson_interval(m["TP"], m["TP"] + m["FP"]) if (m["TP"] + m["FP"]) > 0 else (None, 0.0, 0.0)
        
        prec_str = f"{prec_tuple[0]*100:.1f}% [{prec_tuple[1]*100:.1f}%, {prec_tuple[2]*100:.1f}%]" if prec_tuple[0] is not None else "N/A"
        print(f"\n{cat_name}:")
        print(f"  Recall:    {rec_hat*100:.1f}% [95% CI: {rec_low*100:.1f}% - {rec_high*100:.1f}%]")
        print(f"  FPR:       {fpr_hat*100:.1f}% [95% CI: {fpr_low*100:.1f}% - {fpr_high*100:.1f}%]")
        print(f"  Precision: {prec_str}")

    tot_m = total_sweep[0.55]
    r_hat, r_l, r_h = wilson_interval(tot_m["TP"], tot_m["TP"] + tot_m["FN"])
    f_hat, f_l, f_h = wilson_interval(tot_m["FP"], tot_m["FP"] + tot_m["TN"])
    p_hat, p_l, p_h = wilson_interval(tot_m["TP"], tot_m["TP"] + tot_m["FP"])
    print("\nTOTAL DIRECTED TESTBED (theta = 0.55):")
    print(f"  Recall:    {r_hat*100:.1f}% [95% CI: {r_l*100:.1f}% - {r_h*100:.1f}%]")
    print(f"  FPR:       {f_hat*100:.1f}% [95% CI: {f_l*100:.1f}% - {f_h*100:.1f}%]")
    print(f"  Precision: {p_hat*100:.1f}% [95% CI: {p_l*100:.1f}% - {p_h*100:.1f}%]")
    
    # Analyze Intermixed Experiment as well
    print("\n" + "="*80)
    print("INTERMIXED PGBENCH EXPERIMENT SENSITIVITY SWEEP (155 sessions: 9 Attacks, 146 Benign)")
    print("="*80)
    with open(INTERMIXED_JSON) as f:
        intermixed_data = json.load(f)
    intermixed_sessions = intermixed_data["session_details"]
    im_sweep = analyze_thresholds(intermixed_sessions, thresholds)
    im_roc_auc, im_pr_auc = compute_auc_metrics(intermixed_sessions)
    print(f"Intermixed Benchmark ROC-AUC: {im_roc_auc:.4f}, PR-AUC: {im_pr_auc:.4f}")
    
    for th, m in im_sweep.items():
        prec_str = f"{m['Precision']*100:.1f}%" if m['Precision'] is not None else "N/A"
        print(f"  theta={th:.2f} | TP={m['TP']}/{m['TP']+m['FN']}, FP={m['FP']}/{m['FP']+m['TN']} | Rec={m['Recall']*100:.1f}%, Prec={prec_str}, FPR={m['FPR']*100:.1f}%, F1={m['F1']:.4f}")

    im_m = im_sweep[0.55]
    ir_hat, ir_l, ir_h = wilson_interval(im_m["TP"], im_m["TP"] + im_m["FN"])
    if_hat, if_l, if_h = wilson_interval(im_m["FP"], im_m["FP"] + im_m["TN"])
    ip_hat, ip_l, ip_h = wilson_interval(im_m["TP"], im_m["TP"] + im_m["FP"])
    print("\nINTERMIXED BENCHMARK (theta = 0.55):")
    print(f"  Recall:    {ir_hat*100:.1f}% [95% CI: {ir_l*100:.1f}% - {ir_h*100:.1f}%]")
    print(f"  FPR:       {if_hat*100:.1f}% [95% CI: {if_l*100:.1f}% - {if_h*100:.1f}%]")
    print(f"  Precision: {ip_hat*100:.1f}% [95% CI: {ip_l*100:.1f}% - {ip_h*100:.1f}%]")

    output_data["directed_total"] = {
        "sweep": total_sweep,
        "roc_auc": dir_roc_auc,
        "pr_auc": dir_pr_auc,
        "theta_0.55_metrics": {
            "recall": {"value": r_hat, "ci95": [r_l, r_h]},
            "fpr": {"value": f_hat, "ci95": [f_l, f_h]},
            "precision": {"value": p_hat, "ci95": [p_l, p_h]},
        }
    }
    output_data["intermixed"] = {
        "sweep": im_sweep,
        "roc_auc": im_roc_auc,
        "pr_auc": im_pr_auc,
        "theta_0.55_metrics": {
            "recall": {"value": ir_hat, "ci95": [ir_l, ir_h]},
            "fpr": {"value": if_hat, "ci95": [if_l, if_h]},
            "precision": {"value": ip_hat, "ci95": [ip_l, ip_h]},
        }
    }
    
    out_file = BASE_DIR / "individual_simulation" / "track1_sensitivity_results.json"
    with open(out_file, "w") as f:
        json.dump(output_data, f, indent=2)
    print(f"\n[+] Successfully saved auditable results to: {out_file}")

if __name__ == "__main__":
    main()
