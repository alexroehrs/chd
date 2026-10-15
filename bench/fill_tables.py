"""Regenerates the result tables of main.tex from results/<label>/*.json.

usage (from the repository root): python3 bench/fill_tables.py <path/to/main.tex>
The article source is kept separately (Overleaf); pass the path to its main.tex.
"""
import json
import re
import sys
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

R = Path(__file__).resolve().parent.parent / "results"
TEX = Path(sys.argv[1] if len(sys.argv) > 1 else "paper/main.tex")


def load(label, name):
    return json.loads((R / label / f"{name}.json").read_text())["data"]


def f(x):
    """Latency with three significant digits (half-up rounding), thousands separated."""
    q = "0.01" if x < 10 else "0.1" if x < 100 else "1"
    v = Decimal(str(x)).quantize(Decimal(q), rounding=ROUND_HALF_UP)
    return f"{v:,}"


def t(x):
    """Throughput with one decimal, rounding half up (the JSON keeps two decimals)."""
    return str(Decimal(str(x)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def latency_rows():
    d = load("p2s", "latency")["operations"]
    names = {"create": "Create record", "grant": "Grant access", "read": "Read record",
             "logAccess": "Log access", "revoke": "Revoke access", "erase": "Erase record"}
    comp = {"validateMs": "FHIR validation", "encryptMs": "encrypt", "txMs": "transaction", "uploadMs": "upload",
            "keyShareMs": "key share", "fetchMs": "gateway fetch", "chainCheckMs": "on-chain digest query",
            "decryptMs": "unwrap and decrypt", "totalMs": r"\textbf{total}"}
    rows = []
    for op in names:
        keys = [] if op in ("logAccess", "revoke") else [k for k in d[op] if k != "totalMs"]
        for i, k in enumerate(keys + ["totalMs"]):
            v = d[op][k]
            rows.append(f"{names[op] if i == 0 else ''} & {comp[k]} & {f(v['mean'])} & {f(v['p50'])} & {f(v['p90'])} \\\\")
        rows.append(r"\addlinespace[2pt]")
    return rows[:-1]


def load_rows():
    d = load("p2s", "load")
    high = load("p2s", "load-write-high")["write"]
    names = {"read": "Read", "readAudit": "Read + audit", "write": "Create record"}
    rows = []
    for k in names:
        lst = d[k] + (high if k == "write" else [])
        for i, r in enumerate(lst):
            rows.append(f"{names[k] if i == 0 else ''} & {r['vus']} & {t(r['throughputOpsPerS'])} & "
                        f"{f(r['latencyMs']['p50'])} & {f(r['latencyMs']['p99'])} \\\\")
        rows.append(r"\addlinespace[2pt]")
    return rows[:-1]


def period_rows():
    rows = []
    for label, p in (("p1s", "1"), ("p2s", "2"), ("p5s", "5")):
        o = load(label, "latency")["operations"]
        w = {r["vus"]: r for r in (load(label, "load")["write"] if label == "p2s" else load(label, "load-write")["write"])}
        rows.append(f"{p} & {o['create']['totalMs']['p50'] / 1000:.2f} & {o['grant']['totalMs']['p50'] / 1000:.2f} & "
                    f"{o['read']['totalMs']['p50']:.1f} & {t(w[16]['throughputOpsPerS'])} & {t(w[64]['throughputOpsPerS'])} \\\\")
    return rows


def replace_table(tex, label, rows):
    pat = re.compile(r"(\\label\{" + label + r"\}.*?\\midrule\n)(.*?)(\n\\bottomrule)", re.S)
    new, n = pat.subn(lambda m: m.group(1) + "\n".join(rows) + m.group(3), tex, count=1)
    assert n == 1, label
    return new


tex = TEX.read_text()
tex = replace_table(tex, "tab:latency", latency_rows())
tex = replace_table(tex, "tab:load", load_rows())
tex = replace_table(tex, "tab:period", period_rows())
TEX.write_text(tex)
print("tables updated")
