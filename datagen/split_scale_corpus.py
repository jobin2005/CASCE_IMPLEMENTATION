import json
import random
import sys
from pathlib import Path
from collections import defaultdict

def create_splits(sessions_file: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    
    with open(sessions_file) as f:
        rows = [json.loads(line) for line in f if line.strip()]
        
    family_to_rows = defaultdict(list)
    for row in rows:
        family_to_rows[row["family_id"]].append(row)
        
    families = list(family_to_rows.keys())
    random.seed(42)
    random.shuffle(families)
    
    n = len(families)
    train_f = set(families[:int(n * 0.7)])
    val_f = set(families[int(n * 0.7):int(n * 0.85)])
    test_f = set(families[int(n * 0.85):])
    
    splits = {"train": {}, "val": {}, "test": {}}
    
    for row in rows:
        fid = row["family_id"]
        label = row["label"]
        fname = row["file"]
        
        if fid in train_f:
            splits["train"][fname] = label
        elif fid in val_f:
            splits["val"][fname] = label
        elif fid in test_f:
            splits["test"][fname] = label
            
    for split_name, labels in splits.items():
        with open(out_dir / f"{split_name}_labels.json", "w") as f:
            json.dump(labels, f, indent=2)
            
    print(f"Created splits in {out_dir}")
    print(f"Train: {len(splits['train'])} graphs")
    print(f"Val:   {len(splits['val'])} graphs")
    print(f"Test:  {len(splits['test'])} graphs")

if __name__ == "__main__":
    create_splits(Path(sys.argv[1]), Path(sys.argv[2]))
