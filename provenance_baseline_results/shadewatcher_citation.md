# ShadeWatcher — cited, not reproduced

**Status: cite-only, despite real public code existing.** Same situation as
Kairos: a real reference implementation exists, but the cost of running it
is documented (by its own authors) as prohibitive for this project's scope.

## Citation

**SHADEWATCHER: Recommendation-guided Cyber Threat Analysis using System
Audit Records.** IEEE Symposium on Security and Privacy (Oakland), 2022.
Code: [jun-zeng/ShadeWatcher](https://github.com/jun-zeng/ShadeWatcher)

## Method

Recasts threat detection as a recommendation-system problem: kernel-object
interactions are treated like user-item interactions, encoded into a
knowledge graph via TransR embeddings, and an unsupervised GNN scores how
"expected" each interaction is — an unlikely interaction is a candidate
anomaly. Conceptually the closest of any baseline here to a pure embedding-
similarity approach, rather than a classifier or reconstruction model.

## Why not attempted, specifically

The repository (`audit/`, `parse/`, `recommend/`) is a full C++/Python
pipeline built around parsing raw DARPA Transparent Computing audit logs
into their specific graph format, then training the TransR embedding model.
Per independent third-party analysis of this system (cited in our search,
not our own measurement), **TransR training alone takes up to 12 hours on
one DARPA sub-dataset** — and that cost is reported as the dominant
contributor to ShadeWatcher's overall detection accuracy, meaning it can't
be shortened without materially changing the method. Combined with needing
a custom C++ audit-log parser rewritten for CASCE's schema before any of
that training could even start, this is a multi-day integration effort, not
a baseline we can stand up alongside MAGIC/StreamSpot/FLASH/RT-APT in this
project's timeframe.

## Reported results (as stated in third-party sources — not independently verified)

Reported to miss only 12 of 68,136 malicious interactions on the DARPA
TRACE dataset (roughly 99.98% detection at the interaction/edge level, not
graph-level classification). This is an edge-level metric on DARPA data
under ShadeWatcher's own evaluation protocol — not comparable to this
project's graph-level results on CASCE's corpus, cited only to document
what the paper claims.
