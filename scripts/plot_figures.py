"""Render the manuscript figures from the merged results JSON.

    python3 scripts/plot_figures.py --input results/merged --output results/merged/plots

Replaces the hand-rolled SVG writer in ``cmd/plot`` for FIGURE OUTPUT only.
``cmd/plot`` still writes the audit CSV beside each figure and that stays the
source of truth for the numbers; this script re-plots the same aggregation in
the manuscript's figure style (IEEE single column, vector PDF, 8 pt minimum
type, marker AND line style per system so the figures survive grayscale).

WHAT CHANGED BESIDES THE STYLE
------------------------------
Three defects in the old aggregation are fixed here, because they produced
figures that were not wrong in appearance but wrong in content:

1. **Ref[10]'s two transports were pooled into one curve.** ``vote_transport``
   was not part of the series key, so at concurrency 1/2/4 the figure drew the
   MEDIAN of a Fabric run (1.9 auth/s) and an in-process run (691 auth/s) —
   346, a number neither transport ever produced — and from concurrency 8 on
   drew the in-process arm alone, because the Fabric arm has no points there.
   One curve, spliced from two systems, with a discontinuity at x=8.
   ``docs/experiments.md`` §1.3.1 requires both to be reported; they are two
   curves here.

2. **Ref[13]'s six Exp. 2 configurations were pooled into one point.** arity
   q in {2,5,10} x challenged blocks in {300,460} all landed on B_R=1 with an
   empty dimension map, so the cost-per-request point is a median over six
   different systems spanning 1.56-3.47 ms. ``chartsExp3`` guards this with
   ``sameSetup``; ``chartsExp2`` did not. The first configured setup is
   selected here, as Exp. 3 does.

3. **A log axis was clamped, not refused, on non-positive data.** The old
   ``newAxis`` mapped a zero to ``SmallestNonzeroFloat64``, so Ref[22]'s
   ``proof_size_bytes = 0`` gave exp3-evidence-bytes a y-axis running from
   1e-323 to 1e5 — 328 decades, every curve flattened onto one pixel row, and
   a 68 KB SVG of nothing but tick marks. A log axis is refused here when any
   plotted value is <= 0, and the figure is drawn linear with a warning, which
   is what ``generate_plots.py`` does.

ERROR BARS, AND WHY MOST FIGURES HAVE NONE
------------------------------------------
``config/experiment.yaml`` sets ``meta.repetitions: 1``. A single observation
has no spread, so there is nothing honest to draw. Points backed by one run
are therefore drawn with a HOLLOW marker and the script warns, rather than
drawing a bare marker that reads like a converged measurement. Where several
observations do exist they are pooled only across the repetition index, and
the bar spans observed min..max around the median — not a standard deviation,
which at n=2 is a number with more precision than meaning.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")  # headless: no display on the experiment host
import matplotlib.pyplot as plt  # noqa: E402


# ---------------------------------------------------------------------------
# Style — ported verbatim from the manuscript's generate_plots.py
# ---------------------------------------------------------------------------
# IEEE single-column is 3.5 in. 8 pt is the stated minimum type size, so every
# text element is set at or above it.
plt.rcParams.update({
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 7,
    "figure.figsize": (3.5, 2.6),
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
    "pdf.fonttype": 42,  # embed TrueType rather than Type 3: IEEE requires it
    "ps.fonttype": 42,
})

# Okabe-Ito. Marker AND linestyle both vary so the figures survive grayscale.
MARKERS = ("o", "s", "^", "D", "v", "P", "X")
LINESTYLES = ("-", "--", "-.", ":", (0, (3, 1, 1, 1)), (0, (5, 2)), (0, (1, 1)))
COLORS = ("#0072B2", "#D55E00", "#009E73", "#CC79A7", "#56B4E9", "#E69F00", "#000000")

# The proposed scheme is pinned to slot 0 so its blue circle is the same on
# every figure rather than shifting when a baseline is absent from one.
STYLE_ORDER: Tuple[str, ...] = (
    "zkredact",
    "ref10_emt",
    "ref13_vrbc",
    "ref22_shen",
    # Ref[10]'s two transports are two curves, never one (see module docstring).
    # `ref10_emt` above is the in-process arm — the like-for-like control that
    # belongs in slot 1 — and the Fabric arm takes its own slot rather than
    # borrowing it, or the deployed and the controlled cost would draw
    # identically and the figure could not be read in grayscale.
    "ref10_emt/fabric",
)

# Legend/draw order only — kept separate from STYLE_ORDER so reordering the
# legend can never reassign a system's marker, colour or line style.
LEGEND_ORDER: Tuple[str, ...] = (
    "zkredact", "ref10_emt", "ref10_emt/fabric", "ref13_vrbc", "ref22_shen",
)

LABELS: Dict[str, str] = {
    "zkredact": "ZK-Redact (proposed)",
    "zkredact/plain": "ZK-Redact (no sharding, no batching)",
    "ref10_emt": "Ref[10] EMT (in-process)",
    "ref10_emt/fabric": "Ref[10] EMT (Fabric)",
    "ref13_vrbc": "Ref[13] VRBC",
    "ref22_shen": "Ref[22] Shen",
}

# The ablation and the knob sweeps are arms of ONE system, so their series keys
# miss STYLE_ORDER and would every one of them draw as the same blue circle.
# Each arm is pinned to its own slot, with the complete scheme on slot 0 so the
# proposed configuration keeps the blue circle it holds on every other figure.
ARM_SLOT: Dict[str, int] = {
    "both": 0, "sharding only": 1, "batching only": 2, "neither": 3,
    # Exp. 2's wait-bound and conflict sweeps: ordered arms, styled in order.
    "$\\Delta_R$ = 63 ms": 0, "$\\Delta_R$ = 125 ms": 1,
    "$\\Delta_R$ = 250 ms": 2, "$\\Delta_R$ = 500 ms": 3,
    "conflict 0": 0, "conflict 0.25": 1, "conflict 0.5": 2,
    # Exp. 3's history-depth sweep.
    "depth 1": 0, "depth 2": 1, "depth 4": 2, "depth 8": 3, "depth 16": 4,
}


def style_for(key: str) -> Dict[str, object]:
    # "scheme@ledger" is one system measured at two ledger sizes, which is the
    # whole point of the Exp 3 figure: the system keeps its colour and marker so
    # it is recognisable across figures, and the ledger size picks solid or
    # dashed so the pair reads as a pair. Without this the eight curves all miss
    # STYLE_ORDER and draw identically.
    ledger = None
    if "@" in key:
        key, ledger = key.split("@", 1)

    if key in ARM_SLOT:
        idx = ARM_SLOT[key]
    elif key in STYLE_ORDER:
        idx = STYLE_ORDER.index(key)
    else:
        idx = len(STYLE_ORDER)
    return {
        "marker": MARKERS[idx % len(MARKERS)],
        "linestyle": ("-" if ledger is None or ledger == "100" else "--")
                     if ledger is not None else LINESTYLES[idx % len(LINESTYLES)],
        "color": COLORS[idx % len(COLORS)],
    }


def legend_rank(key: str) -> int:
    if key in LEGEND_ORDER:
        return LEGEND_ORDER.index(key)
    if key in ARM_SLOT:
        return ARM_SLOT[key]
    return 99


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
@dataclass
class Series:
    """One curve. `key` selects the style, `label` is what the legend says."""
    key: str
    label: str
    x: List[float] = field(default_factory=list)
    y: List[float] = field(default_factory=list)
    lo: List[float] = field(default_factory=list)   # observed minimum
    hi: List[float] = field(default_factory=list)   # observed maximum
    n: List[int] = field(default_factory=list)      # repetitions pooled


class Collector:
    """Groups observations into series and aggregates across repetitions ONLY.

    Every dimension that is not the x-axis must already be folded into `key`
    by the caller. Getting that wrong is invisible in the output: pooling an
    arity-2 run with an arity-10 run yields a smooth curve at a value neither
    configuration ever measured, and nothing on the figure says so. That is
    exactly what defect 2 in the module docstring was.
    """

    def __init__(self) -> None:
        self._samples: Dict[Tuple[str, str], Dict[float, List[float]]] = {}

    def add(self, key: str, label: str, x: float, y: float) -> None:
        self._samples.setdefault((key, label), {}).setdefault(float(x), []).append(float(y))

    def series(self) -> List[Series]:
        out: List[Series] = []
        for (key, label), by_x in self._samples.items():
            s = Series(key=key, label=label)
            for x in sorted(by_x):
                ys = by_x[x]
                s.x.append(x)
                s.y.append(statistics.median(ys))
                s.lo.append(min(ys))
                s.hi.append(max(ys))
                s.n.append(len(ys))
            out.append(s)
        out.sort(key=lambda s: (legend_rank(s.key), s.label))
        return out


# ---------------------------------------------------------------------------
# Figure drawing
# ---------------------------------------------------------------------------
@dataclass
class Figure:
    name: str
    xlabel: str
    ylabel: str
    series: List[Series]
    log_x: bool = False
    log_y: bool = False
    notes: List[str] = field(default_factory=list)


def _draw(fig_spec: Figure, out_dir: Path, formats: Sequence[str],
          warnings: List[str]) -> None:
    fig, ax = plt.subplots()
    hollow: List[str] = []

    for s in fig_spec.series:
        # Asymmetric bar: the curve is drawn from the MEDIAN, so the bar spans
        # median-min .. max-median rather than a symmetric sigma the data does
        # not support at these repetition counts.
        yerr = [
            [max(0.0, y - lo) for y, lo in zip(s.y, s.lo)],
            [max(0.0, hi - y) for y, hi in zip(s.y, s.hi)],
        ]
        st = style_for(s.key)
        ax.errorbar(s.x, s.y, yerr=yerr, label=s.label, capsize=2,
                    markersize=3.5, linewidth=1.1, elinewidth=0.8, **st)

        # A point backed by ONE run is not a measurement with a spread, and a
        # filled marker claims otherwise. Draw those hollow — the same device
        # generate_plots.py uses to separate measured from computed points.
        single = [i for i, n in enumerate(s.n) if n < 2]
        if single:
            ax.plot([s.x[i] for i in single], [s.y[i] for i in single],
                    linestyle="none", marker=st["marker"], markersize=3.5,
                    markerfacecolor="white", markeredgecolor=st["color"],
                    markeredgewidth=0.9, zorder=3)
            hollow.append(f"{s.label} {len(single)}/{len(s.n)}")

    # One line per figure, not one per curve: with meta.repetitions at 1 this
    # fires on every series of every figure, and a warning that always fires
    # trains the reader to scroll past the ones that matter.
    if hollow:
        warnings.append(
            f"{fig_spec.name}: single-repetition points, drawn hollow "
            f"(config/experiment.yaml sets meta.repetitions: 1) — "
            + "; ".join(hollow))

    ax.set_xlabel(fig_spec.xlabel)
    ax.set_ylabel(fig_spec.ylabel)

    # LOG AXES ARE REFUSED, NOT CLAMPED, on non-positive data. A log scale drops
    # a zero silently; clamping it to the smallest float (what cmd/plot did)
    # is worse — it keeps the point and destroys the axis around it.
    if fig_spec.log_x:
        xs = [v for s in fig_spec.series for v in s.x]
        if xs and min(xs) > 0:
            ax.set_xscale("log")
        else:
            warnings.append(f"{fig_spec.name}: log x requested but data has a "
                            f"non-positive value; drew linear so nothing is hidden")
    if fig_spec.log_y:
        ys = [v for s in fig_spec.series for v in s.lo]
        if ys and min(ys) > 0:
            ax.set_yscale("log")
        else:
            zero = sorted({s.label for s in fig_spec.series if min(s.lo) <= 0})
            warnings.append(f"{fig_spec.name}: log y requested but "
                            f"{', '.join(zero)} contains a non-positive value; "
                            f"drew linear so nothing is hidden")

    # TICK AT THE SWEPT VALUES, not at decades. The x-axis of every figure here
    # is a swept parameter -- concurrency, workload size, history depth -- and
    # the reader wants to find "512", not to count powers of ten between 10^2
    # and 10^3. Log spacing is kept, so the points stay evenly spaced; only the
    # labels change.
    if ax.get_xscale() == "log":
        ticks = sorted({v for s in fig_spec.series for v in s.x})
        if 0 < len(ticks) <= 14:
            labels = [("%g" % t) for t in ticks]
            ax.set_xticks(ticks)
            # Rotate once the labels are long enough to touch. "256 512 1024"
            # overlaps at the right edge of an 11-tick axis otherwise.
            crowded = len(ticks) > 8 and max(len(l) for l in labels) >= 4
            ax.set_xticklabels(labels, rotation=45 if crowded else 0,
                               ha="right" if crowded else "center")
            ax.xaxis.set_minor_locator(matplotlib.ticker.NullLocator())

    # X-axis breathing room, so the first and last swept points do not sit on
    # the frame and read as clipped.
    if ax.get_xscale() == "log":
        lo, hi = ax.get_xlim()
        if lo > 0 and hi > lo:
            pad = 0.06 * (math.log10(hi) - math.log10(lo))
            ax.set_xlim(10 ** (math.log10(lo) - pad), 10 ** (math.log10(hi) + pad))
    else:
        lo, hi = ax.get_xlim()
        if hi > lo:
            pad = 0.05 * (hi - lo)
            ax.set_xlim(lo - pad, hi + pad)

    # A FLAT CURVE MUST READ AS FLAT. Matplotlib fits the y-axis to the data,
    # so a series that never moves gets an axis zoomed onto its own last
    # decimal place: exp2-wait-bound's four curves are bit-identical at
    # 0.011873, and the default axis ran 0.0114 to 0.0124, drawing four
    # decimal places of nothing as though it were structure. Give a
    # near-constant series a band around its own value instead, so the reader
    # sees a flat line — which is the actual result — rather than magnified
    # noise that is not even noise.
    all_y = [v for s in fig_spec.series for v in s.y]
    if all_y:
        span, mid = max(all_y) - min(all_y), (max(all_y) + min(all_y)) / 2
        if mid != 0 and span / abs(mid) < 0.02:
            warnings.append(
                f"{fig_spec.name}: every plotted value is within "
                f"{span / abs(mid) * 100:.2f}% of {mid:.6g} — the swept "
                f"variable changed nothing; axis widened so the flatness is "
                f"legible as flatness")
            if ax.get_yscale() == "log":
                ax.set_ylim(mid / 2, mid * 2)
            else:
                ax.set_ylim(max(0.0, mid * 0.5), mid * 1.5)

    ax.grid(True, which="major", linewidth=0.3, alpha=0.5)
    if fig_spec.log_x or fig_spec.log_y:
        ax.grid(True, which="minor", linewidth=0.2, alpha=0.3)

    # Legend inside the axes, one entry per row: ncol=1 removes label collision
    # by construction at any figure width. Opaque white, so it covers gridlines
    # cleanly rather than printing over them.
    ax.legend(frameon=True, ncol=1, loc="best", framealpha=1.0,
              facecolor="white", edgecolor="0.7", borderpad=0.3,
              labelspacing=0.22, handlelength=1.5)
    ax.get_legend().get_frame().set_linewidth(0.4)
    _make_room_for_legend(ax, floor_at_zero=not fig_spec.log_y)

    out_dir.mkdir(parents=True, exist_ok=True)
    for ext in formats:
        fig.savefig(out_dir / f"{fig_spec.name}.{ext}",
                    **({"dpi": 300} if ext == "png" else {}))
    plt.close(fig)


def _make_room_for_legend(ax, *, floor_at_zero: bool, max_passes: int = 6) -> None:
    """Grow the y limits, a step at a time, until the legend covers no data.

    generate_plots.py buys the room with a fixed fraction of the data's span.
    That fraction has to be sized for the worst case, so on a six-decade
    figure it spends four empty decades to clear a two-decade legend, and the
    curves end up squeezed into a strip. Measuring the legend once and solving
    for the band in one shot does not work either: `loc="best"` chose its
    corner against the OLD limits, so a single large expansion in that
    direction can be exactly the wrong one.

    So: expand by a small step, redraw — which lets `best` re-choose — and
    stop as soon as no plotted point falls inside the legend frame. It
    converges in one or two passes on most figures and never over-expands.

    Done by extending the LIMITS, never by clipping: no point moves and
    nothing is hidden.
    """
    fig = ax.get_figure()
    step = 0.18  # of the current span, per pass

    # A LEGEND TOO TALL TO CLEAR GOES OUTSIDE, rather than being cleared by
    # growing the axis under it. Exp 3 draws eight curves — four systems at two
    # ledger sizes — and no amount of empty axis fits that inside the frame: six
    # passes at 18% of a six-decade span took the y-axis to 1e14 for data ending
    # at 1e6, squeezing every curve into the bottom third. savefig already
    # trims to a tight bounding box, so an outside legend costs nothing.
    fig.canvas.draw()
    leg = ax.get_legend()
    if leg is not None:
        box = leg.get_window_extent().transformed(ax.transAxes.inverted())
        if box.height > 0.35:
            handles, labels = ax.get_legend_handles_labels()
            leg.remove()
            ax.legend(handles, labels, frameon=True, framealpha=1.0,
                      loc="upper center", bbox_to_anchor=(0.5, -0.24),
                      ncol=2, borderaxespad=0.0)
            ax.get_legend().get_frame().set_linewidth(0.4)
            return

    for _ in range(max_passes):
        fig.canvas.draw()  # nothing has an extent until the figure is laid out
        leg = ax.get_legend()
        if leg is None:
            return
        box = leg.get_window_extent().transformed(ax.transAxes.inverted())
        box = box.expanded(1.06, 1.10)  # a sliver of clearance around the frame

        # Does any drawn point sit under the legend? Work in axes fractions so
        # the test is scale-independent.
        to_axes = ax.transData + ax.transAxes.inverted()
        collides = False
        for line in ax.get_lines():
            data = line.get_xydata()
            if len(data) == 0:
                continue
            for fx, fy in to_axes.transform(data):
                if box.x0 <= fx <= box.x1 and box.y0 <= fy <= box.y1:
                    collides = True
                    break
            if collides:
                break
        if not collides:
            return

        log = ax.get_yscale() == "log"
        lo, hi = ax.get_ylim()
        if log:
            if lo <= 0 or hi <= lo:
                return
            lo, hi = math.log10(lo), math.log10(hi)
        span = hi - lo
        if span <= 0:
            return

        if box.y0 + box.y1 > 1.0:   # legend sits high: grow upward
            hi += step * span
        elif not log and floor_at_zero and lo <= 0:
            # The legend is low but the axis is already on its zero floor, so
            # there is nothing below to give it. Grow upward instead and let
            # the next pass's `best` move the legend into the room that opens.
            hi += step * span
        else:                       # legend sits low: grow downward
            lo -= step * span

        if log:
            ax.set_ylim(10 ** lo, 10 ** hi)
        else:
            # Zero is a real floor: every metric here is a duration, a count,
            # a ratio or a byte size, so the axis must not go below it.
            ax.set_ylim(max(0.0, lo) if floor_at_zero else lo, hi)


# ---------------------------------------------------------------------------
# Experiment 1 — Verification Throughput
# ---------------------------------------------------------------------------
# The headline comparison carries ONE curve per system, at the top of ZK-Redact's
# sweep with native batch verification on: that is the scheme as proposed, and a
# mid-sweep point would report a system nobody designed. The exception is
# Ref[10], which is two curves because it was measured on two transports and
# docs/experiments.md §1.3.1 requires both — `in_process` is the like-for-like
# control against the other three, `fabric` is the deployed cost.
EXP1_FULL_SHARDS, EXP1_FULL_BATCH = 64, 64


def _exp1_key(p: dict) -> Optional[str]:
    """Series key for the headline figures, or None if the point is off-arm.

    Exp 1 compares ZK-Redact against Ref[10] ONLY, and against itself with both
    mechanisms disabled. Ref[13] and Ref[22] are measured but not drawn here:
    neither defines a per-request authorization protocol, so Table I gives them
    "--" for authorization verification cost and their curve would be the cost
    of checking nothing. They remain in Exp 2 and Exp 3, where they perform
    comparable work.

    ZK-Redact appears twice on purpose. The complete scheme is what the
    comparison is against; the (1, 1) arm is the same verification without
    sharding or batching, so the distance between the two is what the mechanisms
    contribute rather than a claim resting on Ref[10]'s consensus cost.
    """
    scheme = p["scheme"]
    if scheme == "zkredact":
        if p.get("native_batch_verify"):
            if (p.get("shard_count") == EXP1_FULL_SHARDS
                    and p.get("proof_batch_size") == EXP1_FULL_BATCH):
                return "zkredact"
            return None
        if p.get("shard_count") == 1 and p.get("proof_batch_size") == 1:
            return "zkredact/plain"
        return None
    if scheme == "ref10_emt":
        # THE FIX. Without the transport in the key these two pool into one
        # median of 1.9 and 691 authorizations/s.
        return "ref10_emt/fabric" if p.get("vote_transport") == "fabric" else "ref10_emt"
    return None  # Ref[13] and Ref[22]: see the docstring


def _ablation_arm(p: dict) -> Optional[str]:
    if p["scheme"] != "zkredact" or p.get("native_batch_verify"):
        return None  # the ablation is about the two knobs, not the third
    s, b = p.get("shard_count"), p.get("proof_batch_size")
    return {
        (1, 1): "neither",
        (EXP1_FULL_SHARDS, 1): "sharding only",
        (1, EXP1_FULL_BATCH): "batching only",
        (EXP1_FULL_SHARDS, EXP1_FULL_BATCH): "both",
    }.get((s, b))


def _upto(series: List[Series], xmax: float) -> List[Series]:
    """The same curves, truncated to x <= xmax."""
    out = []
    for s in series:
        keep = [i for i, x in enumerate(s.x) if x <= xmax]
        if keep:
            out.append(Series(s.key, s.label,
                              [s.x[i] for i in keep], [s.y[i] for i in keep],
                              [s.lo[i] for i in keep], [s.hi[i] for i in keep],
                              [s.n[i] for i in keep]))
    return out


def figures_exp1(result: dict) -> List[Figure]:
    tp, lat, abl = Collector(), Collector(), Collector()
    for p in result["points"]:
        key = _exp1_key(p)
        if key:
            tp.add(key, LABELS[key], p["concurrency"], p["authorized_requests_per_second"])
            lat.add(key, LABELS[key], p["concurrency"], p["latency"]["p50_ns"] / 1e6)
        arm = _ablation_arm(p)
        if arm:
            abl.add(arm, arm, p["concurrency"], p["authorized_requests_per_second"])

    return [
        Figure("exp1-throughput", "number of concurrent requests",
               "verification throughput (requests/s)", tp.series(),
               log_x=True, log_y=True,
               notes=["Ref[10] is two curves: only its Fabric arm is charged "
                      "consensus.",
                      "ZK-Redact appears complete and with both mechanisms "
                      "disabled; the gap between them is what sharding and "
                      "batching contribute.",
                      "Ref[13] and Ref[22] define no per-request authorization "
                      "protocol (Table I) and are not drawn; they appear in "
                      "Exp 2 and Exp 3."]),
        # Same figure over the range EVERY system reached. Ref[10]'s Fabric arm
        # stops at 512 because its chaincode dies above that, so on the full
        # sweep it alone ends early and reads as missing data. Cut to the common
        # range, all four curves span the same axis and the comparison is
        # like-for-like at every point.
        Figure("exp1-throughput-512", "number of concurrent requests",
               "verification throughput (requests/s)", _upto(tp.series(), 512),
               log_x=True, log_y=True,
               notes=["Ref[10]'s Fabric arm ends at 256: its chaincode "
                      "terminates above that, so the level was not measured.",
                      "The full sweep to 1024 is in exp1-throughput."]),
        Figure("exp1-latency-p50", "concurrency (closed loop)",
               "p50 authorization latency (ms)", lat.series(), log_x=True, log_y=True),
        Figure("exp1-ablation", "concurrency (closed loop)",
               "authorizations / s", abl.series(), log_x=True, log_y=True,
               notes=["ZK-Redact only; 'on' means the top of each sweep, 64."]),
    ]


# ---------------------------------------------------------------------------
# Experiment 2 — Redaction Throughput
# ---------------------------------------------------------------------------
def figures_exp2(result: dict) -> List[Figure]:
    points = result["points"]

    # The headline holds both knobs fixed, for the reason Exp. 1 does: a
    # comparison figure compares systems. The wait bound is read from the
    # schemes that HAVE one — a baseline does not batch and records 0, so a
    # plain minimum would select 0 and match no ZK-Redact point at all.
    waits = [p["wait_bound_ms"] for p in points if p["wait_bound_ms"] > 0]
    head_wait = min(waits) if waits else 0
    head_ratio = min(p["conflict_ratio"] for p in points)

    # THE FIX for defect 2: Ref[13] sweeps arity q and challenged blocks on
    # Exp. 2 as well as Exp. 3, and those are separate systems, not repetitions.
    # Hold each scheme at its first configured setup, exactly as Exp. 3 does.
    first_setup: Dict[str, dict] = {}
    for p in points:
        sp = p.get("setup_params")
        if sp and p["scheme"] not in first_setup:
            first_setup[p["scheme"]] = sp

    def same_setup(p: dict) -> bool:
        want = first_setup.get(p["scheme"])
        return want is None or (p.get("setup_params") or {}) == want

    batches = lambda p: p["wait_bound_ms"] > 0  # noqa: E731

    cost, share, stale, wait, conf = (Collector() for _ in range(5))
    overhead = Collector()
    # The top of the batch sweep, read from the points: it is where ZK-Redact is
    # drawn as the complete scheme on the headline figure.
    full_batch = max(p["batch_size"] for p in points)
    for p in points:
        if not same_setup(p):
            continue
        x = p["batch_size"]
        # The manuscript's Exp 2 figure: overhead per request against workload
        # size, one curve per system. ZK-Redact at the top of its batch sweep;
        # the baselines do not batch and sit at B_R=1 by construction.
        if p.get("workload_size", 0) > 0                 and (not batches(p) or p["wait_bound_ms"] == head_wait)                 and p["conflict_ratio"] == head_ratio                 and (not batches(p) or p["batch_size"] == full_batch):
            k = p["scheme"]
            overhead.add(k, LABELS[k], p["workload_size"],
                         p["cost_per_request_ns"] / 1e6)
        on_head = (not batches(p) or p["wait_bound_ms"] == head_wait) \
            and p["conflict_ratio"] == head_ratio
        if on_head:
            k = p["scheme"]
            cost.add(k, LABELS[k], x, p["cost_per_request_ns"] / 1e6)
            share.add(k, LABELS[k], x, p["crypto_share"])
            stale.add(k, LABELS[k], x, p["stale_exclusion_rate"])
        if p["scheme"] == "zkredact":
            if p["conflict_ratio"] == head_ratio:
                arm = f"$\\Delta_R$ = {p['wait_bound_ms']} ms"
                wait.add(arm, arm, x, p["stale_exclusion_rate"])
            if not batches(p) or p["wait_bound_ms"] == head_wait:
                arm = f"conflict {p['conflict_ratio']:g}"
                conf.add(arm, arm, x, p["cost_per_request_ns"] / 1e6)

    return [
        Figure("exp2-overhead", "number of redaction requests",
               "average processing overhead (ms/request)",
               overhead.series(), log_x=True, log_y=True,
               notes=["One curve per system. ZK-Redact is the complete scheme, "
                      "at the top of its batch sweep; the baselines do not batch.",
                      f"Wait bound {head_wait} ms, conflict ratio {head_ratio:g}."]),
        Figure("exp2-cost-per-request", "$B_R$ (redactions per batch)",
               "cost per request (ms)", cost.series(), log_x=True, log_y=True,
               notes=["$B_R$=1 is the batching-disabled arm and the point every "
                      "baseline sits at.",
                      f"Wait bound {head_wait} ms, conflict ratio {head_ratio:g}; "
                      "both are swept in their own figures."]),
        Figure("exp2-crypto-share", "$B_R$ (redactions per batch)",
               "CryptoTime / TotalTime", share.series(), log_x=True),
        Figure("exp2-staleness", "$B_R$ (redactions per batch)",
               "fraction excluded on freshness", stale.series(), log_x=True),
        Figure("exp2-wait-bound", "$B_R$ (redactions per batch)",
               "fraction excluded on freshness", wait.series(), log_x=True,
               notes=["ZK-Redact only; no baseline batches, so none has a wait bound."]),
        Figure("exp2-conflict", "$B_R$ (redactions per batch)",
               "cost per request (ms)", conf.series(), log_x=True, log_y=True),
    ]


# ---------------------------------------------------------------------------
# Experiment 3 — Provenance Audit Cost
# ---------------------------------------------------------------------------
def figures_exp3(result: dict) -> List[Figure]:
    points = result["points"]
    head_depth = min(p["history_depth"] for p in points)

    first_setup: Dict[str, dict] = {}
    for p in points:
        sp = p.get("setup_params")
        if sp and p["scheme"] not in first_setup:
            first_setup[p["scheme"]] = sp

    def same_setup(p: dict) -> bool:
        want = first_setup.get(p["scheme"])
        return want is None or (p.get("setup_params") or {}) == want

    cost, evidence, depth = Collector(), Collector(), Collector()
    audit = Collector()
    for p in points:
        if not same_setup(p):
            continue
        x = p["ledger_size"]
        k = p["scheme"]
        # The manuscript's Exp 3 figure: verification time against history
        # depth, each scheme drawn once per ledger size. The SLOPE is the
        # scheme's dependence on depth; the GAP between its pair is its
        # dependence on ledger size, so a ledger-independent audit shows as two
        # coincident curves. Verification only — retrieval is a transport cost
        # and is reported separately.
        arm_key = f"{k}@{x}"
        audit.add(arm_key, f"{LABELS[k]}, L={x}", p["history_depth"],
                  p["verification_time_ns"] / 1e6)
        if p["history_depth"] == head_depth:
            cost.add(k, LABELS[k], x, p["total_time_ns"] / 1e6)
            evidence.add(k, LABELS[k], x, p["proof_size_bytes"])
        if k == "zkredact":
            arm = f"depth {p['history_depth']}"
            depth.add(arm, arm, x, p["total_time_ns"] / 1e6)

    notes = [f"History depth fixed at {head_depth}; the ledger grows.",
             "Auditor authorization is excluded and reported separately: no "
             "baseline has that step."]
    for name, sc in sorted(result.get("ledger_scaling", {}).items()):
        if not sc.get("claim_holds", True):
            notes.append(f"WARNING: {name} declares a ledger-independent audit "
                         f"but scaled {sc['class']} (cost x{sc['cost_ratio']:.2f} "
                         f"over ledger x{sc['size_ratio']:.0f})")

    return [
        Figure("exp3-audit", "number of redactions in transaction history",
               "audit verification time (ms)", audit.series(),
               log_x=True, log_y=True,
               notes=["Each scheme is drawn once per ledger size L. The slope is "
                      "its dependence on history depth; the gap between a "
                      "scheme's pair is its dependence on ledger size.",
                      "Coincident curves mean a ledger-independent audit.",
                      "Verification only; retrieval latency and the auditor "
                      "authorization adder are reported separately."]),
        Figure("exp3-audit-cost", "ledger size (blocks)",
               "retrieval + verification (ms)", cost.series(),
               log_x=True, log_y=True, notes=notes),
        # log_y is REQUESTED, and the guard will refuse it while Ref[22] reports
        # zero evidence bytes. That refusal is the honest outcome: a zero on a
        # log axis is either dropped or, as cmd/plot did, clamped to 1e-323 and
        # allowed to stretch the axis over 328 decades.
        Figure("exp3-evidence-bytes", "ledger size (blocks)",
               "evidence transferred (bytes)", evidence.series(),
               log_x=True, log_y=True),
        Figure("exp3-history-depth", "ledger size (blocks)",
               "retrieval + verification (ms)", depth.series(),
               log_x=True, log_y=True,
               notes=["ZK-Redact only: depth is how many times the target has "
                      "already been redacted."]),
    ]


BUILDERS: Dict[str, Callable[[dict], List[Figure]]] = {
    "exp1_verification": figures_exp1,
    "exp2_redaction": figures_exp2,
    "exp3_audit": figures_exp3,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 scripts/plot_figures.py")
    ap.add_argument("--input", default="results/merged",
                    help="directory holding the merged results JSON")
    ap.add_argument("--output", default="results/merged/plots",
                    help="directory to write the figures into")
    ap.add_argument("--format", default="pdf,png",
                    help="comma-separated output formats (pdf is the vector one)")
    ap.add_argument("--scale", type=float, default=1.0,
                    help="multiply the figure size; 1.0 is IEEE single column")
    args = ap.parse_args(argv)

    if args.scale != 1.0:
        w, h = plt.rcParams["figure.figsize"]
        plt.rcParams["figure.figsize"] = (w * args.scale, h * args.scale)

    in_dir, out_dir = Path(args.input), Path(args.output)
    formats = [f.strip() for f in args.format.split(",") if f.strip()]

    paths = sorted(in_dir.glob("*.json"))
    if not paths:
        print(f"error: no results JSON in {in_dir}", file=sys.stderr)
        return 1

    warnings: List[str] = []
    written = 0
    for path in paths:
        doc = json.loads(path.read_text())
        exp = doc.get("metadata", {}).get("experiment")
        if exp not in BUILDERS:
            print(f"  skip {path.name}: experiment {exp!r} has no figures")
            continue
        # A partial comparison must never be read as a comparison.
        if doc["metadata"].get("partial_comparison"):
            warnings.append(f"{exp}: metadata records a PARTIAL COMPARISON — "
                            f"not every system ran")
        for spec in BUILDERS[exp](doc["result"]):
            if not spec.series:
                warnings.append(f"{spec.name}: no series matched; not drawn")
                continue
            _draw(spec, out_dir, formats, warnings)
            written += 1
            print(f"  {spec.name:24s} {len(spec.series)} series")
            for note in spec.notes:
                print(f"      {note}")

    print(f"\nwrote {written} figure(s) to {out_dir}")
    if warnings:
        print(f"\n{len(warnings)} warning(s):")
        for w in warnings:
            print(f"  ! {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
