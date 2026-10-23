"""Builds the article figures from results/<label>/*.json (requires matplotlib).

usage: python3 bench/plot.py [label] [output-dir]   (defaults: p2s, <repo>/figures)
"""
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
label = sys.argv[1] if len(sys.argv) > 1 else "p2s"
out = Path(sys.argv[2] if len(sys.argv) > 2 else ROOT / "figures")
out.mkdir(parents=True, exist_ok=True)
res = ROOT / "results" / label

from matplotlib import font_manager  # noqa: E402

for _f in Path("/usr/share/texmf/fonts/opentype/public/tex-gyre").glob("texgyretermes-*.otf"):
    font_manager.fontManager.addfont(str(_f))
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["TeX Gyre Termes", "Times New Roman", "DejaVu Serif"], "mathtext.fontset": "stix", "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8,
    "legend.fontsize": 7, "xtick.labelsize": 7, "ytick.labelsize": 7,
    "axes.spines.top": False, "axes.spines.right": False, "figure.dpi": 300,
})
C = {"chd": "#2b6cb0", "base": "#c05621", "read": "#2b6cb0", "audit": "#2f855a", "write": "#c05621", "grey": "#718096"}
COL_W = 3.35  # inches, one column of the JISA two-column layout


def load(name):
    return json.loads((res / f"{name}.json").read_text())["data"]


def fig_gas():
    d = load("gas")
    order = ["registerRecord", "updateRecord", "grantAccess", "revokeAccess", "logAccess", "eraseRecord", "setEncryptionKey", "setInstitution"]
    fig, (a, b) = plt.subplots(1, 2, figsize=(2 * COL_W, 2.1), gridspec_kw={"width_ratios": [1.25, 1]})
    vals = [d["operations"][k]["gas"]["mean"] / 1000 for k in order]
    a.barh(order[::-1], vals[::-1], color=C["chd"])
    for y, v in enumerate(vals[::-1]):
        a.text(v + 1, y, f"{v:.1f}k", va="center", fontsize=6.5)
    a.set_xlabel("mean gas per transaction (thousands)")
    a.set_ylabel("registry function")
    a.set_title("(a) gas cost of the CHD registry functions")
    a.set_xlim(0, max(vals) * 1.25)
    sizes = [r["payloadBytes"]["mean"] / 1024 for r in d["baseline"]]
    base = [r["gas"]["mean"] for r in d["baseline"]]
    chd = d["operations"]["registerRecord"]["gas"]["mean"]
    b.loglog(sizes, base, "o-", color=C["base"], label="encrypted record on-chain (baseline)")
    b.loglog(sizes, [chd] * len(sizes), "s--", color=C["chd"], label="CHD (digest on-chain)")
    b.set_xlabel("encrypted payload size (KiB)")
    b.set_ylabel("gas per write (log scale)")
    b.set_title("(b) gas per write vs. encrypted payload size")
    b.legend(frameon=False, loc="upper left", fontsize=6)
    b.set_ylim(3e4, 3e9)
    fig.tight_layout()
    fig.savefig(out / "gas.pdf")
    plt.close(fig)


def fig_crypto():
    d = load("crypto")["rows"]
    kib = [r["plaintextBytes"] / 1024 for r in d]
    fig, ax = plt.subplots(figsize=(COL_W, 2.1))
    for key, lab, col, mk in [("validateSerializeMs", "FHIR validation + serialization", C["grey"], "^"),
                              ("sealMs", "seal (AES-GCM + SHA-256 + key wrap)", C["chd"], "o"),
                              ("openMs", "open (unwrap + verify + decrypt + parse)", C["audit"], "s")]:
        p50 = [r[key]["p50"] for r in d]
        p90 = [r[key]["p90"] for r in d]
        ax.errorbar(kib, p50, yerr=[[0] * len(p50), [b - a for a, b in zip(p50, p90)]], fmt=mk + "-", color=col,
                    label=lab, capsize=2, ms=3, lw=1)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks([1, 4, 16, 64, 256, 1024])
    ax.set_xticklabels(["1", "4", "16", "64", "256", "1024"])
    ax.set_xlabel("FHIR Bundle size (KiB, log scale)")
    ax.set_ylabel("client-side time (ms, log scale)\nmedian, bar up to p90")
    ax.legend(frameon=False, fontsize=6)
    fig.tight_layout()
    fig.savefig(out / "crypto.pdf")
    plt.close(fig)


def fig_load():
    d = load("load")
    try:
        d["write"] = d["write"] + load("load-write-high")["write"]
    except FileNotFoundError:
        pass
    fig, (a, b) = plt.subplots(1, 2, figsize=(2 * COL_W, 2.35))
    styles = [("read", "read", C["read"], "o", "-"), ("readAudit", "read + audit", C["audit"], "s", "--"),
              ("write", "create record", C["write"], "^", "-")]
    for key, lab, col, mk, ls in styles:
        rows = d[key]
        vus = [r["vus"] for r in rows]
        a.plot(vus, [r["throughputOpsPerS"] for r in rows], marker=mk, ls=ls, color=col, label=lab, ms=3.5, lw=1.1)
        b.plot(vus, [r["latencyMs"]["p50"] for r in rows], marker=mk, ls=ls, color=col, ms=3.5, lw=1.1)
        b.plot(vus, [r["latencyMs"]["p99"] for r in rows], marker=mk, ls=":", color=col, ms=2, lw=0.9, alpha=0.6)
    ticks = [1, 4, 16, 64, 128, 256]
    for ax in (a, b):
        ax.set_xscale("log", base=2)
        ax.set_xticks(ticks)
        ax.set_xticklabels([str(t) for t in ticks])
        ax.set_xlabel("concurrent clients (log scale)")
        ax.set_yscale("log")
    a.set_ylabel("throughput (operations/s, log scale)")
    b.set_ylabel("latency (ms, log scale)")
    a.set_title("(a) throughput per workload")
    b.set_title("(b) latency per workload")
    from matplotlib.lines import Line2D
    b.legend(
        handles=[Line2D([], [], color=C["grey"], ls="-", lw=1.1, label="median (p50)"),
                 Line2D([], [], color=C["grey"], ls=":", lw=0.9, label="99th percentile (p99)")],
        frameon=False, fontsize=6, loc="center left",
    )
    h, l = a.get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.0))
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    fig.savefig(out / "load.pdf")
    plt.close(fig)


for f in (fig_gas, fig_crypto, fig_load):
    try:
        f()
        print(f"ok {f.__name__}")
    except FileNotFoundError as e:
        print(f"skip {f.__name__}: {e}")
