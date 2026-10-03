#!/usr/bin/env python3
"""Simulation of Paper P26: 'Deep Learning in Cybersecurity: A Hybrid BERT-LSTM Network for SQL Injection Attack Detection' (Liu & Dai, IET 2024).
"""

import json
import sys
from pathlib import Path
import networkx as nx
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import casce_metrics as cm

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "baseline_models"

MAX_SEQ_LEN = 50
EMBED_DIM = 64
HIDDEN_DIM = 64
BATCH_SIZE = 32
EPOCHS = 10
SEED = 42

def extract_session_sql_tokens(G: nx.MultiDiGraph):
    sql_texts = []
    for _, d in G.nodes(data=True):
        if d.get("type") == "Query":
            text = d.get("query") or d.get("query_text") or d.get("label") or ""
            if text:
                sql_texts.append(str(text).lower())
    return " ".join(sql_texts) if sql_texts else "empty_query"

def load_split(name: str):
    labels = json.loads((SPLITS_DIR / f"{name}_labels.json").read_text())
    texts, y = [], []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        texts.append(extract_session_sql_tokens(G))
        y.append(int(label))
    return texts, np.array(y)

class BERTLSTMModel(nn.Module):
    def __init__(self, vocab_size, embed_dim=EMBED_DIM, hidden_dim=HIDDEN_DIM):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers=2, batch_first=True, bidirectional=True)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, 32),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(32, 1)
        )
        
    def forward(self, x):
        embedded = self.embedding(x)
        out, (hn, cn) = self.lstm(embedded)
        pooled = torch.max(out, dim=1)[0]
        return self.fc(pooled).squeeze(-1)

class SQLDataset(Dataset):
    def __init__(self, sequences, labels):
        self.x = torch.tensor(sequences, dtype=torch.long)
        self.y = torch.tensor(labels, dtype=torch.float32)
        
    def __len__(self):
        return len(self.x)
        
    def __getitem__(self, idx):
        return self.x[idx], self.y[idx]

def main():
    torch.manual_seed(SEED)
    print("[P26 Simulation - Liu & Dai IET 2024] Loading SQL token sequences...")
    train_texts, y_train = load_split("train")
    val_texts, y_val = load_split("val")
    test_texts, y_test = load_split("test")
    
    word2idx = {"<PAD>": 0, "<UNK>": 1}
    for text in train_texts:
        for word in text.split():
            if word not in word2idx:
                word2idx[word] = len(word2idx)
                
    vocab_size = len(word2idx)
    print(f"Vocabulary size: {vocab_size}")
    
    def tokenize_and_pad(texts):
        seqs = []
        for text in texts:
            tokens = [word2idx.get(w, 1) for w in text.split()][:MAX_SEQ_LEN]
            padded = tokens + [0] * (MAX_SEQ_LEN - len(tokens))
            seqs.append(padded)
        return np.array(seqs)
        
    X_train = tokenize_and_pad(train_texts)
    X_val = tokenize_and_pad(val_texts)
    X_test = tokenize_and_pad(test_texts)
    
    train_loader = DataLoader(SQLDataset(X_train, y_train), batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(SQLDataset(X_val, y_val), batch_size=BATCH_SIZE)
    test_loader = DataLoader(SQLDataset(X_test, y_test), batch_size=BATCH_SIZE)
    
    model = BERTLSTMModel(vocab_size)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCEWithLogitsLoss()
    
    best_val_loss = float("inf")
    best_state = None
    
    print("Training BERT-LSTM hybrid model...")
    for epoch in range(1, EPOCHS + 1):
        model.train()
        train_loss = 0.0
        for bx, by in train_loader:
            optimizer.zero_grad()
            logits = model(bx)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * len(by)
        train_loss /= len(train_loader.dataset)
        
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for bx, by in val_loader:
                logits = model(bx)
                val_loss += criterion(logits, by).item() * len(by)
        val_loss /= len(val_loader.dataset)
        
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            
    if best_state is not None:
        model.load_state_dict(best_state)
        
    model.eval()
    val_probs = []
    with torch.no_grad():
        for bx, _ in val_loader:
            val_probs.append(torch.sigmoid(model(bx)))
    val_probs = torch.cat(val_probs).numpy()
    theta = cm.best_f1_threshold(y_val, val_probs)
    
    test_probs = []
    with torch.no_grad():
        for bx, _ in test_loader:
            test_probs.append(torch.sigmoid(model(bx)))
    test_probs = torch.cat(test_probs).numpy()
    report = cm.binary_report(y_test, test_probs, theta)
    
    print(f"\n[P26 BERT-LSTM Results]:")
    print(f"  theta={theta:.3f} | acc={report['accuracy']:.4f} | prec={report['precision']:.4f} | rec={report['recall']:.4f} | f1={report['f1']:.4f} | fpr={report['fpr']:.4f}")
    
    out_file = OUT_DIR / "p26_bert_lstm_results.json"
    out_file.write_text(json.dumps(report, indent=2, default=float))
    print(f"Saved P26 results to {out_file}")

if __name__ == "__main__":
    main()
