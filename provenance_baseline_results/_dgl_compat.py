"""Compatibility shim: import this BEFORE `import dgl` anywhere in the MAGIC
integration.

dgl 2.1.0 eagerly imports dgl.distributed -> dgl.graphbolt at package-load
time (used for multi-machine training / GraphBolt's newer sampling backend),
neither of which MAGIC's batch-level (self-supervised, single-process)
training path ever touches. Both pull in a torchdata API surface
(torchdata.datapipes, torchdata.dataloader2) that this environment's
torchdata (0.11.0) removed, so a bare `import dgl` fails before any MAGIC
code even runs.

Verified unused: MAGIC's train.py/eval.py/autoencoder.py only call
dgl.from_networkx, dgl.batch, and dgl.sampling.global_uniform_negative_sampling
-- none of which touch dgl.distributed or dgl.graphbolt. Stubbing these two
submodules out (rather than downgrading/reinstalling dgl or torchdata, which
risked more disk churn on an already near-full disk) is a disclosed,
narrowly-scoped workaround, not a silent behavior change.
"""
import sys
import types


class _StubDistributedClass:
    def __init__(self, *a, **k):
        raise RuntimeError(
            "dgl.distributed.DistGraph/DistDataLoader was called, but this shim "
            "stubbed it out on the assumption MAGIC's batch-level training never "
            "uses it. If you see this, the assumption above was wrong."
        )


def install():
    if "dgl.distributed" not in sys.modules:
        dist_mod = types.ModuleType("dgl.distributed")
        dist_mod.DistGraph = _StubDistributedClass
        dist_mod.DistDataLoader = _StubDistributedClass
        sys.modules["dgl.distributed"] = dist_mod

    if "dgl.graphbolt" not in sys.modules:
        gb_mod = types.ModuleType("dgl.graphbolt")
        gb_mod.__getattr__ = lambda attr: (_ for _ in ()).throw(
            AttributeError(f"dgl.graphbolt.{attr} stubbed out (unused by MAGIC batch-level training)")
        )
        sys.modules["dgl.graphbolt"] = gb_mod


install()
