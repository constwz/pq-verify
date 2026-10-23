#!/usr/bin/env python3
"""Check the real CLI and measurement artifacts; these are not performance results."""

import collections
import csv
import hashlib
import math
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile


def read_rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


CASES = 8
FALLBACK_BACKENDS = {"mldsa-native/C", "PQClean/clean"}


def run(binary, directory, output, cases, rounds, *extra):
    arguments = [
        str(binary), "--algorithms", "all", "--cases", cases,
        "--keys", "2", "--messages-per-key", "1", "--message-bytes", "32",
        "--rounds", str(rounds), "--warmup-ms", "1", "--duration-ms", "1",
        "--latency-samples", "64", "--out", output, *extra,
    ]
    return subprocess.run(arguments, cwd=directory, capture_output=True, text=True)


def main():
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="pq-verify-smoke-") as temporary:
        root = Path(temporary)
        # Preparation is never gated on CPU dispatch: corpus bytes do not depend on it.
        prepared = run(binary, root, "unused", "valid", 1, "--prepare-only")
        assert prepared.returncode == 0, prepared.stderr
        assert not (root / "unused").exists()
        listed = {
            name: digest
            for digest, name in (line.split("  ") for line in prepared.stdout.splitlines())
        }
        assert len(listed) == 17
        for name, digest in listed.items():
            assert hashlib.sha256((root / "corpus" / name).read_bytes()).hexdigest() == digest
        again = run(binary, root, "unused", "valid", 1, "--prepare-only")
        assert again.returncode == 0 and again.stdout == prepared.stdout, again.stderr
        assert "Generating" not in again.stderr

        # Functional check only, so it must also pass where CPU detection is blocked.
        first = run(binary, root, "first", "all", 2, "--raw-latency", "--allow-fallback")
        assert first.returncode == 0, first.stderr
        assert (root / "first/COMPLETE").exists()
        rows = read_rows(root / "first/rounds.csv")
        assert len(rows) == 17 * CASES * 2
        assert {"corrupt-head", "corrupt-mid", "corrupt-tail"} <= {r["case"] for r in rows}
        observations = collections.defaultdict(list)
        for row in read_rows(root / "first/latency.csv"):
            key = (row["algorithm"], row["case"], row["round"])
            observations[key].append(int(row["elapsed_ns"]))
        hashes = {}
        for row in rows:
            key = (row["algorithm"], row["case"], row["round"])
            samples = sorted(observations[key])
            assert len(samples) == int(row["latency_samples"]) == 64
            assert math.isclose(statistics.mean(samples), float(row["mean_ns"]), abs_tol=0.001)
            for percentile in (50, 95, 99):
                expected = samples[math.ceil(len(samples) * percentile / 100) - 1]
                assert expected == int(row[f"p{percentile}_ns"])
            elapsed = int(row["throughput_elapsed_ns"])
            assert elapsed >= 1_000_000
            rate = int(row["throughput_calls"]) * 1e9 / elapsed
            assert math.isclose(rate, float(row["verify_per_second"]), abs_tol=0.001)
            corpus = root / "corpus" / f'{row["algorithm"]}-k2-n1-m32.bin'
            hashes[row["algorithm"]] = hashlib.sha256(corpus.read_bytes()).hexdigest()
            assert row["corpus_sha256"] == hashes[row["algorithm"]] == listed[corpus.name]
            assert row["backend"] and row["hash_backend"]

        metadata = (root / "first/metadata.txt").read_text()
        fell_back = "dist_build=true" in metadata and any(
            row["backend"] in FALLBACK_BACKENDS for row in rows
        )
        budget = ("--latency-max-ms", "1")
        if fell_back:
            gated = run(binary, root, "replay", "valid", 1, *budget)
            assert gated.returncode != 0 and "--allow-fallback" in gated.stderr
            assert not (root / "replay").exists()
            budget += ("--allow-fallback",)
        replay = run(binary, root, "replay", "valid", 1, *budget)
        assert replay.returncode == 0, replay.stderr
        for row in read_rows(root / "replay/rounds.csv"):
            assert row["corpus_sha256"] == hashes[row["algorithm"]]
            assert 1 <= int(row["latency_samples"]) <= 64
        assert (root / "replay/COMPLETE").exists()

        # Existing output and damaged corpus must fail, never silently overwrite.
        assert run(binary, root, "first", "valid", 1, "--allow-fallback").returncode != 0
        damaged = root / "corpus/ML-DSA-44-k2-n1-m32.bin"
        data = bytearray(damaged.read_bytes())
        data[-1] ^= 1
        damaged.write_bytes(data)
        assert run(binary, root, "damaged", "valid", 1, "--allow-fallback").returncode != 0
        assert not (root / "damaged/COMPLETE").exists()
    gate = "rejected without --allow-fallback" if fell_back else "native dispatch"
    print(f"PASS: 17 algorithms × {CASES} cases × 2 rounds; corpus preparation, raw "
          f"statistics, corpus replay, latency budget and failure handling ({gate})")


if __name__ == "__main__":
    main()
