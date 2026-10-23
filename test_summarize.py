"""Unit tests for summarize.py; run with `python3 -m unittest test_summarize`."""

import contextlib
import csv
import io
import math
import tempfile
import unittest
from pathlib import Path

import summarize

HEADER = (
    "algorithm,backend,hash_backend,category,case,round,keys,messages_per_key,message_bytes,"
    "corpus_sha256,pk_bytes,input_sig_min_bytes,input_sig_mean_bytes,input_sig_max_bytes,"
    "latency_samples,mean_ns,p50_ns,p95_ns,p99_ns,throughput_calls,throughput_elapsed_ns,"
    "verify_per_second"
).split(",")


def row(algorithm, round_, p50, rate, **overrides):
    values = dict.fromkeys(HEADER, "0")
    values.update(
        algorithm=algorithm,
        backend="b",
        hash_backend="h",
        case="valid",
        round=str(round_),
        keys="8",
        messages_per_key="8",
        message_bytes="32",
        corpus_sha256=f"corpus-{algorithm.split('@')[0]}",
        p50_ns=str(p50),
        p99_ns=str(2 * p50),
        verify_per_second=str(rate),
    )
    values.update(overrides)
    return values


class SummarizeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def run_dir(self, name, mode, rows, header=HEADER, complete=True):
        directory = self.root / name
        directory.mkdir()
        (directory / "metadata.txt").write_text(
            f"mode=pure-message-api\nliboqs_revision=x\nmode={mode}\n"
        )
        with (directory / "rounds.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, header, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        if complete:
            (directory / "COMPLETE").write_text("done\n")
        return directory

    def summarize(self, *directories, baseline="ML-DSA-44"):
        rows = [r for d in directories for r in summarize.load(d)]
        return summarize.summarize(rows, baseline)

    def test_statistics_are_medians_over_rounds(self):
        rounds = [(100, 10), (300, 30), (200, 20)]
        d = self.run_dir(
            "a", "optimized", [row("ML-DSA-44", i, p50, rate) for i, (p50, rate) in enumerate(rounds, 1)]
        )
        [s] = self.summarize(d)
        self.assertEqual(
            (s["rounds"], s["p50_median_ns"], s["p50_min_ns"], s["p50_max_ns"]), (3, 200, 100, 300)
        )
        self.assertEqual(s["p99_median_ns"], 400)
        self.assertEqual(s["verify_per_second_median"], 20.0)
        self.assertAlmostEqual(s["verify_per_second_cv"], math.sqrt(200 / 3) / 20)
        self.assertEqual(s["throughput_vs_baseline"], 1.0)

    def test_throughput_is_relative_to_baseline_within_build_and_case(self):
        d = self.run_dir(
            "a",
            "optimized",
            [
                row("ML-DSA-44", 1, 1, 20),
                row("Falcon-512", 1, 1, 5),
                row("Falcon-512", 1, 1, 7, case="wrong-key"),
            ],
        )
        ratio = {(s["algorithm"], s["case"]): s["throughput_vs_baseline"] for s in self.summarize(d)}
        self.assertEqual(ratio[("Falcon-512", "valid")], 0.25)
        self.assertEqual(ratio[("Falcon-512", "wrong-key")], "")

    def test_builds_and_workloads_stay_separate(self):
        optimized = self.run_dir(
            "o",
            "optimized",
            [row("ML-DSA-44", 1, 1, 30), row("ML-DSA-44", 1, 1, 9, keys="64", corpus_sha256="other")],
        )
        portable = self.run_dir("p", "portable", [row("ML-DSA-44", 1, 1, 10)])
        groups = {(s["build"], s["keys"]) for s in self.summarize(optimized, portable)}
        self.assertEqual(groups, {("optimized", "8"), ("optimized", "64"), ("portable", "8")})

    def test_different_corpora_for_one_parameter_set_are_rejected(self):
        a = self.run_dir("a", "optimized", [row("SLH_DSA_PURE_SHA2_128S", 1, 1, 1)])
        b = self.run_dir(
            "b",
            "optimized",
            [row("SLH_DSA_PURE_SHA2_128S@boringssl", 1, 1, 1, corpus_sha256="other")],
        )
        with self.assertRaisesRegex(ValueError, "different corpora"):
            self.summarize(a, b)

    def test_incomplete_run_is_rejected_by_cli(self):
        d = self.run_dir("a", "optimized", [row("ML-DSA-44", 1, 1, 1)], complete=False)
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(summarize.main([str(d)]), 1)
        self.assertIn("COMPLETE", stderr.getvalue())

    def test_results_without_hash_backend_column_still_load(self):
        header = [name for name in HEADER if name != "hash_backend"]
        d = self.run_dir("a", "portable", [row("ML-DSA-44", 1, 1, 1)], header=header)
        [s] = self.summarize(d)
        self.assertEqual(s["hash_backend"], "")

    def test_cli_writes_csv_and_counts_a_directory_once(self):
        d = self.run_dir("a", "optimized", [row("ML-DSA-44", 1, 5, 2)])
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(summarize.main([str(d), str(d)]), 0)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(lines[0].split(","), list(summarize.FIELDS))
        self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
