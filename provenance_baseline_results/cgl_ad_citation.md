# CGL-AD — cited, not reproduced

**Status: cite-only.** Unlike MAGIC, StreamSpot, and RT-APT (all reproduced
against our own corpus under our own protocol — see `magic_results.json`,
`streamspot_results.json`, `rtapt_results.json`), CGL-AD is not reproduced
here. No public code repository could be found for it (checked GitHub search
and the paper's own venue listing); the only available artifact is the
published paper itself. Re-implementing an undocumented temporal-graph
pipeline from a paper description alone, with no reference code to check
against, risks silently misrepresenting the method — safer to cite it
honestly than to guess at an implementation and call it "CGL-AD."

## Citation

**A dynamic provenance graph-based detector for advanced persistent
threats.** *Expert Systems with Applications*, 2024.
DOI: [10.1016/j.eswa.2024.125877](https://doi.org/10.1016/j.eswa.2024.125877)

## Method, as described in the paper (not independently verified by us)

CGL-AD ("Contextualized Graph Learning APT Detector") combines three
components on *dynamic* (streaming/temporal) provenance graphs:

1. **Temporal graph learning** to capture structural transformations across
   time (i.e., across a sequence of graph snapshots, not a single static
   graph).
2. **Hash-based data stream frequency estimation** to detect local
   topological changes — the same general family of technique as RT-APT's
   FlexSketch and our own StreamHash-based StreamSpot re-implementation,
   but applied incrementally over a stream rather than once per static
   graph.
3. **Sequence learning** over the resulting embeddings, to model how a
   session's structure evolves over time rather than classifying one fixed
   snapshot.

This is architecturally a different problem setting from CASCE's own design
and from every other baseline in this comparison: CASCE (and MAGIC,
StreamSpot, RT-APT, FLASH, classical ML, and the GNN baselines) all classify
a **complete, already-finished session graph**. CGL-AD is built around
**incremental classification of an evolving stream** — it does not have a
natural "one-shot on a finished graph" mode without ourselves inventing a
non-standard adaptation, which is exactly the kind of unfaithful
re-implementation this writeup is trying to avoid.

## Reported results (as stated in the paper's abstract — not independently verified)

The paper reports evaluation on three datasets: **StreamSpot, Camflow-apt,
and Shellshock**, claiming CGL-AD outperforms the strongest baseline in
their own comparison (**FLASH**) by **+1.5%, +3.7%, and +5.6% ROC-AUC**
respectively, on those three datasets. These are *relative* improvement
figures stated in the abstract; the paper's absolute precision/recall/F1
numbers were not accessible to us (the full article is paywalled on
ScienceDirect, and no preprint or code release could be located). **Do not
treat the figures above as directly comparable to this project's own
measured numbers** — they were computed by CGL-AD's authors, on different
datasets (StreamSpot/Camflow-apt/Shellshock, not CASCE's corpus), using
their own FLASH baseline implementation, not ours. They are cited here only
to characterize what CGL-AD claims relative to a paper's own baselines, not
as a row in our results table.

## Why not attempted

- No public reference implementation exists to check a re-implementation
  against, unlike MAGIC (FDUDSDE/MAGIC), StreamSpot (the original algorithm
  is simple enough to implement faithfully from the paper), FLASH
  (DART-Laboratory/Flash-IDS), and RT-APT (luannd4869/RT-APT).
- The method is designed for streaming/temporal graphs, not the
  complete-static-session-graph setting every other model in this
  comparison uses — adapting it would require a design decision (how to
  "streamify" CASCE's already-complete session graphs) not specified by the
  paper, which would make any resulting number our own invention, not
  CGL-AD's.
