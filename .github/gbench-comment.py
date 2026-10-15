#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Render a google-benchmark comparison as a Markdown PR comment section.

Reads the file written by `compare.py --dump_to_json` and prints one table row
per benchmark: the median CPU time on master and on the PR, its change, the
spread of the repetitions (coefficient of variation) and the U test p-value.
Benchmarks whose CPU time p-value is not below alpha are folded under a
<details> block. Rows are grouped by the first two parts of the benchmark name
after `BM_`.
"""

import argparse
import json
import sys

# Mark the change as noisy if the coefficient of variation of either run
# is above this.
NOISY_CV = 0.05

# Report the wall-clock time if its change differs from the CPU time change
# by more than this.
WALL_CPU_DISAGREEMENT = 0.03

OTHER_GROUP = "other"


def change(old, new):
    return (new - old) / old if old else 0.0


def fmt_change(value):
    text = "{:+.1%}".format(value)
    return "0.0%" if text in ("+0.0%", "-0.0%") else text


def fmt_time(value):
    return "{:.0f}".format(value) if value >= 100 else "{:.3g}".format(value)


def fmt_cv(value):
    pct = value * 100
    return "{:.2f}%".format(pct) if pct < 1 else "{:.1f}%".format(pct)


def fmt_pvalue(value):
    if value is None:
        return "n/a"
    return "<0.001" if value < 0.001 else "{:.3f}".format(value)


def collect(diff_report):
    """Group the diff report entries by benchmark name.

    The U test result sits on the entry of the individual repetitions
    (named like the benchmark), the aggregates sit on entries named
    `<benchmark>_<aggregate>`.
    """
    benches = {}
    order = []

    def bench(name):
        if name not in benches:
            benches[name] = {"name": name, "utest": {}, "unit": "", "agg": {}}
            order.append(name)
        return benches[name]

    geomean = None
    for entry in diff_report:
        if entry["name"] == "OVERALL_GEOMEAN":
            geomean = entry
            continue
        if entry.get("run_type") == "aggregate":
            aggregate = entry.get("aggregate_name", "")
            suffix = "_" + aggregate
            if not aggregate or not entry["name"].endswith(suffix):
                continue
            b = bench(entry["name"][: -len(suffix)])
            b["agg"][aggregate] = entry["measurements"][0]
            if aggregate == "median":
                b["unit"] = entry["time_unit"]
        else:
            b = bench(entry["name"])
            b["utest"] = entry.get("utest") or {}
            if "median" not in b["agg"] and len(entry["measurements"]) == 1:
                # No repetitions: the single run stands in for the median.
                b["agg"]["median"] = entry["measurements"][0]
                b["unit"] = entry["time_unit"]

    return [benches[name] for name in order if "median" in benches[name]["agg"]], geomean


def cpu_cv(b):
    """Return the CPU time coefficient of variation of (master, PR)."""
    cv = b["agg"].get("cv")
    if cv is not None:
        return cv["cpu_time"], cv["cpu_time_other"]
    mean = b["agg"].get("mean")
    stddev = b["agg"].get("stddev")
    if mean is None or stddev is None or not mean["cpu_time"] or not mean["cpu_time_other"]:
        return None
    return (
        stddev["cpu_time"] / mean["cpu_time"],
        stddev["cpu_time_other"] / mean["cpu_time_other"],
    )


def cpu_pvalue(b):
    return b["utest"].get("cpu_pvalue")


def is_significant(b, alpha):
    pvalue = cpu_pvalue(b)
    # Without a U test we cannot tell, so do not hide the result.
    return pvalue is None or pvalue < alpha


def group(benches):
    """Group the benchmarks by the first two name parts after `BM_`.

    The group prefix then extends over all the name parts that every member
    shares. A group of one benchmark goes to OTHER_GROUP. Group all the
    benchmarks at once, so a folded benchmark keeps the heading of its family. Returns a list of
    (prefix, [(row name, benchmark)]).
    """
    groups = {}
    order = []
    for b in benches:
        parts = b["name"].split("_")
        key = tuple(parts[:3]) if len(parts) > 3 else None
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(b)

    result = []
    other = list(groups.pop(None, []))
    for key in order:
        members = groups.get(key)
        if members is None:
            continue
        if len(members) == 1:
            other.extend(members)
            continue
        split = [b["name"].split("_") for b in members]
        # Leave at least one name part for each row.
        depth = len(key)
        limit = min(len(parts) for parts in split) - 1
        while depth < limit and len({parts[depth] for parts in split}) == 1:
            depth += 1
        prefix = "_".join(split[0][:depth]) + "_"
        result.append(
            (prefix + "*", [(b["name"][len(prefix):], b) for b in members])
        )
    if other:
        other.sort(key=lambda b: benches.index(b))
        result.append((OTHER_GROUP, [(b["name"], b) for b in other]))
    return result


def table(rows):
    lines = [
        "| Benchmark | Median CPU time, master → PR | Change | Spread (cv) | p-value |",
        "|---|--:|--:|--:|--:|",
    ]
    for name, b in rows:
        median = b["agg"]["median"]
        old, new = median["cpu_time"], median["cpu_time_other"]
        cv = cpu_cv(b)
        change_cell = fmt_change(change(old, new))
        if cv is None:
            cv_cell = "n/a"
        else:
            cv_cell = "{} → {}".format(fmt_cv(cv[0]), fmt_cv(cv[1]))
            if max(cv) > NOISY_CV:
                change_cell += " (noisy)"
        lines.append(
            "| `{}` | {} → {} {} | {} | {} | {} |".format(
                name,
                fmt_time(old),
                fmt_time(new),
                b["unit"],
                change_cell,
                cv_cell,
                fmt_pvalue(cpu_pvalue(b)),
            )
        )
    return "\n".join(lines)


def render_groups(groups, keep, out):
    for prefix, rows in groups:
        rows = [(name, b) for name, b in rows if keep(b)]
        if not rows:
            continue
        out.append("#### `{}`".format(prefix) if prefix != OTHER_GROUP else "#### Other")
        out.append("")
        out.append(table(rows))
        out.append("")


def wall_cpu_notes(benches):
    notes = []
    for b in benches:
        median = b["agg"]["median"]
        wall = change(median["real_time"], median["real_time_other"])
        cpu = change(median["cpu_time"], median["cpu_time_other"])
        if abs(wall - cpu) > WALL_CPU_DISAGREEMENT:
            notes.append(
                "- `{}`: wall-clock {}, CPU {}".format(
                    b["name"], fmt_change(wall), fmt_change(cpu)
                )
            )
    return notes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diff_json", help="output of compare.py --dump_to_json")
    parser.add_argument("--alpha", type=float, default=0.05)
    args = parser.parse_args()

    with open(args.diff_json) as f:
        benches, geomean = collect(json.load(f))

    groups = group(benches)
    significant = [b for b in benches if is_significant(b, args.alpha)]
    unchanged = [b for b in benches if not is_significant(b, args.alpha)]

    out = []
    if geomean is not None:
        m = geomean["measurements"][0]
        out.append("Overall geomean of the CPU time: {}.".format(fmt_change(m["cpu"])))
        out.append("")
    out.append(
        "The spread is the coefficient of variation (stddev / mean) of the"
        " repetitions. A change is noisy if the spread of either run is above"
        " {:.0%}. A benchmark is listed here if the U test p-value of its CPU"
        " time is below {}.".format(NOISY_CV, args.alpha)
    )
    out.append("")
    if significant:
        render_groups(groups, lambda b: is_significant(b, args.alpha), out)
    else:
        out.append("No statistically significant changes.")
        out.append("")

    notes = wall_cpu_notes(benches)
    if notes:
        out.append("Wall-clock time and CPU time disagree for:")
        out.append("")
        out.extend(notes)
        out.append("")

    if unchanged:
        out.append("<details>")
        out.append(
            "<summary>{} benchmark(s) with no statistically significant"
            " change</summary>".format(len(unchanged))
        )
        out.append("")
        render_groups(groups, lambda b: not is_significant(b, args.alpha), out)
        out.append("</details>")
        out.append("")

    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()
