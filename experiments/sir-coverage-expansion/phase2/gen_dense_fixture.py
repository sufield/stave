#!/usr/bin/env python3
# Phase 2 dense worst-case fixture generator.
#
# The auto_prop projector is ASSET-TYPE-SCOPED: for an asset of type T it emits
# auto_prop_<path> only for the property paths that controls applicable to T
# actually read. So the worst case is not "N assets x every catalog path" — it
# is "for each asset type, that type's paths", replicated K times.
#
# This script parses applicable_asset_types + field: paths from the control
# YAML, builds a type->paths map, and emits a bundle-shaped obs.v0.1 snapshot
# with K assets per type, each populated (boolean leaf) at every path its type
# reads. Bundle shape is used deliberately: it routes through ParseBundle and
# skips the strict per-timestamp jsonschema (which would reject boolean leaves
# where it wants string/number) — fine for a fact-count / wall-time experiment.
#
#   K=10 python3 gen_dense_fixture.py <controls-dir> <out-observations-dir>
import os, re, json, glob, sys

controls = sys.argv[1] if len(sys.argv) > 1 else "controls"
outdir   = sys.argv[2] if len(sys.argv) > 2 else "/tmp/dense/observations"
K = int(os.environ.get("K", "1"))

type_paths = {}
for f in glob.glob(controls + "/**/*.yaml", recursive=True):
    txt = open(f, encoding="utf-8", errors="replace").read()
    m = re.search(r"applicable_asset_types:\s*\n((?:\s*-\s*\S+\n)+)", txt)
    types = re.findall(r"-\s*(\S+)", m.group(1)) if m else []
    paths = set(re.findall(r"field:\s*properties\.([A-Za-z0-9_.]+)", txt))
    for t in types:
        type_paths.setdefault(t, set()).update(paths)

def nest(paths):
    root = {}
    for p in sorted(paths):
        parts = p.split("."); d = root
        for i, k in enumerate(parts):
            if i == len(parts) - 1:
                if not isinstance(d.get(k), dict):
                    d[k] = True
            else:
                if not isinstance(d.get(k), dict):
                    d[k] = {}
                d = d[k]
    return root

assets = []
for t, paths in sorted(type_paths.items()):
    for i in range(K):
        assets.append({"id": f"{t}-{i}", "type": t, "vendor": "aws",
                       "properties": nest(paths)})

bundle = {"schema_version": "obs.v0.1", "snapshots": [
    {"schema_version": "obs.v0.1", "captured_at": "2026-05-09T00:00:00Z",
     "source": "deployed", "assets": assets}]}
os.makedirs(outdir, exist_ok=True)
json.dump(bundle, open(os.path.join(outdir, "bundle.json"), "w"))
pairs = sum(len(v) for v in type_paths.values())
print(f"types={len(type_paths)} (type,path)-pairs={pairs} "
      f"max-paths-per-type={max(len(v) for v in type_paths.values())} "
      f"assets={len(assets)} (K={K})")
