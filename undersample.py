import os
import json
import random

train_runs = 42
base_dev = "output/dataset_dev"

total_normal_before = 0
total_attack = 0
total_normal_after = 0

retained_ratio = 0.20  # Keep 20% of Normal traffic

for i in range(1, train_runs + 1):
    run_dir = os.path.join(base_dev, f"run_{i}")
    in_json = os.path.join(run_dir, "labels_train_noheldout.json")
    out_json = os.path.join(run_dir, "labels_train_undersampled.json")
    
    if not os.path.exists(in_json):
        continue
        
    with open(in_json, "r") as f:
        data = json.load(f)
        
    filtered = {}
    for k, v in data.items():
        if v == 1:
            filtered[k] = 1
            total_attack += 1
        elif v == 0:
            total_normal_before += 1
            if random.random() < retained_ratio:
                filtered[k] = 0
                total_normal_after += 1

    with open(out_json, "w") as f:
        json.dump(filtered, f, indent=2)

print(f"Undersampling complete!")
print(f"Orig Normal: {total_normal_before}")
print(f"Orig Attack: {total_attack}")
print(f"New Normal:  {total_normal_after}")
print(f"New Attack:  {total_attack}")
print(f"Written to labels_train_undersampled.json in runs 1-{train_runs}")
