#!/usr/bin/env python3
"""
Homogeneous GNN Baseline Architectures
======================================
Owner: Member 1 (Jobin - Comparative Baselines)

This script compresses the highly specific Heterogeneous Network mapping from CASCE 
into standard unified Homogeneous `Data` tensors. We then train generic `GCNConv` 
and `SAGEConv` algorithms to establish a mathematical baseline proving why CASCE's 
HeteroGAT architecture is vastly superior.

NOTE: This script natively requires Torch & Torch_Geometric.
"""

import os
import json
import torch
import torch.nn.functional as F
import networkx as nx
from pathlib import Path
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

try:
    from torch_geometric.data import Data, DataLoader
    from torch_geometric.nn import GCNConv, SAGEConv, global_mean_pool
except ImportError:
    print("[!] FATAL: PyTorch_Geometric not located on this partition.")
    print("    This occurs due to local disk space limitations (PEP 668).")
    print("    To evaluate this comparative module, please load the dataset onto a GPU workstation with PyG installed.")
    exit(1)

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / 'output'
TRAIN_VAL_SPLIT = 42

NODE_TYPES = {"Query": 0, "Process": 1, "File": 2, "Table": 3, "Endpoint": 4, "Role": 5, "Behavior": 6}

def compress_graph_to_homogeneous(G, y_label):
    """
    Strips heterogeneous edge keys and converts all node attributes into 
    one unified homogeneous tensor feature map to mimic raw GCN processing.
    """
    node_mapping = {n: i for i, n in enumerate(G.nodes())}
    x = torch.zeros((G.number_of_nodes(), len(NODE_TYPES) + 2), dtype=torch.float)
    
    for n, data in G.nodes(data=True):
        idx = node_mapping[n]
        t = data.get("type", "Process")
        t_idx = NODE_TYPES.get(t, 1)
        x[idx, t_idx] = 1.0 # one-hot type embedding
        x[idx, len(NODE_TYPES)] = float(G.in_degree(n))
        x[idx, len(NODE_TYPES) + 1] = float(G.out_degree(n))
        
    edge_index = []
    for u, v in G.edges():
        edge_index.append([node_mapping[u], node_mapping[v]])
        
    if len(edge_index) > 0:
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        
    y = torch.tensor([y_label], dtype=torch.long)
    return Data(x=x, edge_index=edge_index, y=y)

def load_pyg_dataset(runs_dir, run_range=None):
    pyg_graphs = []
    if not runs_dir.exists(): return pyg_graphs
    
    runs = sorted([d for d in os.listdir(runs_dir) if d.startswith('run_')], 
                  key=lambda x: int(x.split('_')[1]))
                  
    if run_range:
        runs = [r for r in runs if run_range[0] <= int(r.split('_')[1]) <= run_range[1]]
        
    print(f"Loading GraphMLs from {runs_dir.name} and compressing to Homogeneous Data Tensors...")
    for run in runs:
        run_path = runs_dir / run
        lbl_file = run_path / 'labels.json'
        if not lbl_file.exists(): continue
        
        with open(lbl_file) as f:
            run_labels = json.load(f)
            
        for fname, y in run_labels.items():
            g_path = run_path / fname
            if g_path.exists():
                try:
                    G = nx.read_graphml(g_path)
                    data = compress_graph_to_homogeneous(G, y)
                    pyg_graphs.append(data)
                except Exception as e:
                    pass
    return pyg_graphs


class HomogeneousGCN(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels):
        super().__init__()
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.lin = torch.nn.Linear(hidden_channels, 2)
        
    def forward(self, data):
        # Ignore discrete edge connections natively
        x, edge_index, batch = data.x, data.edge_index, data.batch
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        x = global_mean_pool(x, batch)
        x = F.dropout(x, p=0.3, training=self.training)
        return self.lin(x)


class HomogeneousSAGE(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels):
        super().__init__()
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)
        self.lin = torch.nn.Linear(hidden_channels, 2)
        
    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        x = global_mean_pool(x, batch)
        x = F.dropout(x, p=0.3, training=self.training)
        return self.lin(x)


def evaluate(model, loader, device):
    model.eval()
    all_preds, all_true = [], []
    for data in loader:
        data = data.to(device)
        out = model(data)
        preds = out.argmax(dim=1).cpu().numpy()
        all_preds.extend(preds)
        all_true.extend(data.y.cpu().numpy())
        
    if len(np.unique(all_true)) < 2: return 0.0, 0.0, 0.0, 0.0
    
    prec = precision_score(all_true, all_preds, zero_division=0)
    rec = recall_score(all_true, all_preds, zero_division=0)
    f1 = f1_score(all_true, all_preds, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(all_true, all_preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    return prec, rec, f1, fpr

def train_baseline(model_name, ModelClass, train_loader, val_loader, test_loader, device, num_features):
    model = ModelClass(in_channels=num_features, hidden_channels=32).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.005, weight_decay=5e-4)
    criterion = torch.nn.CrossEntropyLoss()
    
    print(f"\n=========================================")
    print(f" TRAINING BASELINE: {model_name} ")
    print(f"=========================================")
    
    patience = 5
    best_f1 = 0
    epochs_no_improve = 0
    
    for epoch in range(1, 31):
        model.train()
        total_loss = 0
        for data in train_loader:
            data = data.to(device)
            optimizer.zero_grad()
            out = model(data)
            loss = criterion(out, data.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            
        _, _, val_f1, _ = evaluate(model, val_loader, device)
        print(f"Epoch {epoch:02d} | Train Loss: {total_loss/len(train_loader):.4f} | Val F1: {val_f1:.4f}")
        
        if val_f1 > best_f1:
            best_f1 = val_f1
            epochs_no_improve = 0
            torch.save(model.state_dict(), f"{model_name.replace(' ', '_')}_best.pt")
        else:
            epochs_no_improve += 1
            if epochs_no_improve >= patience:
                # Early stopping limits the baseline model natively
                break
                
    # Final Test
    model.load_state_dict(torch.load(f"{model_name.replace(' ', '_')}_best.pt"))
    prec, rec, f1, fpr = evaluate(model, test_loader, device)
    print(f"\n=== FINAL {model_name.upper()} RESULTS ===")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print("=========================================\n")


def main():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Executing over PyTorch engine: {device}")
    
    train_data = load_pyg_dataset(OUTPUT_DIR / 'dataset_dev', (1, TRAIN_VAL_SPLIT))
    val_data = load_pyg_dataset(OUTPUT_DIR / 'dataset_dev', (TRAIN_VAL_SPLIT + 1, 999))
    test_data = load_pyg_dataset(OUTPUT_DIR / 'dataset_test')
    
    if len(train_data) == 0 or len(test_data) == 0:
        print("Failure: Could not load testing sets from output directory.")
        return
        
    num_features = len(NODE_TYPES) + 2
    train_loader = DataLoader(train_data, batch_size=32, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=32, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=32, shuffle=False)
    
    # Execute Model 1: GCN
    train_baseline("Homogeneous GCN", HomogeneousGCN, train_loader, val_loader, test_loader, device, num_features)
    
    # Execute Model 2: GraphSAGE
    train_baseline("Homogeneous GraphSAGE", HomogeneousSAGE, train_loader, val_loader, test_loader, device, num_features)

if __name__ == '__main__':
    import numpy as np
    main()
