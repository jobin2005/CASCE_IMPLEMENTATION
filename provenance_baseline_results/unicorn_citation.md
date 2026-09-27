# Unicorn — cited, not reproduced

**Status: cite-only, despite real public code existing.** Same category as
Kairos and ShadeWatcher: real code found, but the integration cost is
higher than this project's remaining scope justifies right now — not "no
code exists," which would be a different (and weaker) reason.

## Citation

**UNICORN: Runtime Provenance-Based Detector for Advanced Persistent
Threats.** NDSS 2020. [arXiv:2001.01525](https://arxiv.org/abs/2001.01525) ·
Code: [crimson-unicorn](https://github.com/crimson-unicorn) (org, split
across `parsers`, `modeler`, `core`, `analyzer`, `plot` repos)

## Method

Streams a provenance graph and periodically summarizes it into a
fixed-size **graph sketch** via incremental histogram sketching (their own
"HistoSketch" technique — the same general family as RT-APT's FlexSketch
and our StreamHash-based StreamSpot re-implementation, but computed
incrementally over a live stream rather than once per finished graph). A
clustering-based model captures normal execution dynamics; sketches that
fall outside the learned clusters at deployment time are flagged.

## Why not attempted, specifically

Unlike RT-APT (one self-contained Jupyter notebook, light Python
dependencies, adaptable in an afternoon), Unicorn's real implementation is
split across five separate repositories orchestrated via a wiki-documented
multi-stage pipeline (log parsing → sketch construction → clustering model
→ analysis/plotting), each a separate integration surface. Reproducing it
faithfully would mean standing up that whole pipeline against CASCE's
schema, which is a substantially larger effort than any of the four
baselines actually reproduced in this project (MAGIC, StreamSpot, FLASH,
RT-APT were each single-script/notebook adaptations). Flagged as feasible
future work if the team wants to invest more time here, not ruled out on
principle.

## Reported results (as stated in the paper's own Table II — not independently verified)

On the StreamSpot dataset: **StreamSpot's own baseline** reaches precision
0.74, accuracy 0.66; **Unicorn** (their R=1 setting, roughly comparable
conditions) reaches precision 0.51, recall 1.0, accuracy 0.60 — i.e., higher
recall than StreamSpot but lower precision, on their benchmark. These are
numbers from the original NDSS 2020 paper's own comparison table, on the
original StreamSpot dataset, not CASCE's corpus — cited to document what
Unicorn claims relative to StreamSpot on its own terms, not as a row in our
results table.
