# CASCE Cross-Layer PostgreSQL Dataset

## Description
This dataset captures PostgreSQL 18.4 database queries mapped to underlying Linux OS Kernel events via eBPF. 
It contains 100,000+ normal pgbench workload transactions against standard schemas (simulating real-world scenarios), alongside explicit attack simulations.

**Artifacts Generated Without Pre-Correlation / Graph Fusion:**
- `postgres_events.json`: Contains Session ID, Backend PID, Database, SQL Query, Event Type, Timestamp.
- `kernel_events.json`: Contains PID, Parent PID, Timestamp, Syscall arguments (from eBPF libbpf/BCC).
- `labels.csv`: Maps PostgreSQL Session IDs to threat labels mapped from controlled attack timings.
- `attack_scripts/`: Shell scripts that were used to insert deterministic malicious sequences into the dataset.

_Algorithm 1 & AI pipeline processing are designed to ingest this frozen baseline._
