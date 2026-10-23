#!/usr/bin/env python3
"""Summarize finished pq-verify runs across rounds (stdlib only).

Rows are grouped by build, algorithm, backend, case and workload. Each statistic
is a median over rounds, so one noisy round cannot dominate. Incomplete runs and
runs that measured one parameter set on different corpora are rejected: their
numbers are not comparable.
"""

import argparse
import csv
import re
import statistics
import sys
from pathlib import Path

WORKLOAD = ("keys", "messages_per_key", "message_bytes")
GROUP = ("build", "algorithm", "backend", "hash_backend", "case", *WORKLOAD)
FIELDS = (
    *GROUP,
    "rounds",
    "p50_median_ns",
    "p50_min_ns",
    "p50_max_ns",
    "p99_median_ns",
    "verify_per_second_median",
    "verify_per_second_cv",
    "throughput_vs_baseline",
)


def load(directory):
    directory = Path(directory)
    if not (directory / "COMPLETE").exists():
        raise ValueError(f"{directory}: no COMPLETE marker; not a finished run")
    # metadata.txt also contains mode=pure-message-api; only the provenance line
    # names the build.
    match = re.search(
        r"^mode=(optimized|portable)$", (directory / "metadata.txt").read_text(), re.MULTILINE
    )
    if match is None:
        raise ValueError(f"{directory}: metadata.txt names no build mode")
    with (directory / "rounds.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        row["build"] = match.group(1)
        row.setdefault("hash_backend", "")
    return rows


def summarize(rows, baseline):
    corpora = {}
    groups = {}
    for row in rows:
        workload = tuple(row[name] for name in WORKLOAD)
        # Alternative implementations (NAME@provider) reuse the parameter set's corpus.
        parameter_set = row["algorithm"].split("@")[0]
        expected = corpora.setdefault((parameter_set, workload), row["corpus_sha256"])
        if row["corpus_sha256"] != expected:
            raise ValueError(f"{parameter_set} {workload}: runs used different corpora")
        groups.setdefault(tuple(row[name] for name in GROUP), []).append(row)

    summary = []
    for key, members in sorted(groups.items()):
        p50 = [int(r["p50_ns"]) for r in members]
        rate = [float(r["verify_per_second"]) for r in members]
        summary.append(
            {
                **dict(zip(GROUP, key)),
                "rounds": len(members),
                "p50_median_ns": statistics.median(p50),
                "p50_min_ns": min(p50),
                "p50_max_ns": max(p50),
                "p99_median_ns": statistics.median(int(r["p99_ns"]) for r in members),
                "verify_per_second_median": statistics.median(rate),
                "verify_per_second_cv": statistics.pstdev(rate) / statistics.fmean(rate),
            }
        )

    def scope(entry):
        return (entry["build"], entry["case"], *(entry[name] for name in WORKLOAD))

    reference = {
        scope(s): s["verify_per_second_median"] for s in summary if s["algorithm"] == baseline
    }
    for s in summary:
        base = reference.get(scope(s))
        s["throughput_vs_baseline"] = s["verify_per_second_median"] / base if base else ""
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Summarize pq-verify runs across rounds.")
    parser.add_argument(
        "--baseline",
        default="ML-DSA-44",
        help="algorithm whose median verify/s is 1.0 in throughput_vs_baseline",
    )
    parser.add_argument("runs", nargs="+", type=Path, help="finished result directories")
    args = parser.parse_args(argv)
    try:
        directories = dict.fromkeys(path.resolve() for path in args.runs)
        rows = [row for directory in directories for row in load(directory)]
        summary = summarize(rows, args.baseline)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    writer = csv.DictWriter(sys.stdout, FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
