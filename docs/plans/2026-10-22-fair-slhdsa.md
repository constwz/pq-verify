# pq-verify SLH-DSA 公平对比 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让本工具能给出两份可信的跨算法族对比——“算法本身”（三族都用纯 C）和“上线成本”（三族都用优化实现）——并在目标 x86 Linux 服务器上产出正式数据。

**Architecture:** 分三个阶段，按顺序执行。阶段一新增跨轮汇总脚本，用现有可移植构建出算法层面对比；阶段二接入 BoringSSL 的 SLH-DSA-SHA2-128s（硬件 SHA-256）作为第二个实现，与 liboqs 同名参数集共用同一份样本；阶段三提供正式测试脚本和在目标硬件上的操作手册。

**Tech Stack:** Rust 1.93 / edition 2024（无 crates.io 依赖）、liboqs 0.16.0、BoringSSL（固定提交）、CMake、Python 3 标准库、Bash 3.2+。

**Spec:** 本计划承接 `README.zh-CN.md` 第 4 节“跨算法族比较时，SLH-DSA 处于明显劣势”。可行性已在本地验证（2026-10-22，Apple M 系列）：

- BoringSSL 主线提交 `af41e135bc1714981fb8a791e9dda4fc6ff140c3` 提供 FIPS 205 pure 接口 `SLHDSA_SHA2_128S_{generate_key,sign,verify}`，SHA-256 走中间状态预计算 + 硬件指令（ARMv8 SHA2 / x86 SHA-NI）。
- liboqs 生成的签名 BoringSSL 能验过，反之亦然；篡改消息后两者都拒绝。
- 验签耗时：liboqs 约 475 µs，BoringSSL 约 81 µs，约 5.9 倍。
- BoringSSL 的 SHAKE-256f 也是纯 C Keccak，实测比 liboqs 慢约 15%，不改变结论，**不接入**。
- 两个静态库没有重名符号；BoringSSL 的 `libcrypto.a` 依赖 C++ 运行时（macOS `libc++`，Linux `libstdc++`）。
- 在受限沙箱里 CMake 的编译器探测会失败，原生构建必须在普通环境中运行。

## Global Constraints

- 基准工具保持独立 Cargo workspace，**不引入 crates.io 依赖**，不依赖 NewL1 仓库的任何代码。
- liboqs 固定 `5a1a854b0dc9f2141bdc771c555ee60c37950183`（0.16.0）；BoringSSL 固定 `af41e135bc1714981fb8a791e9dda4fc6ff140c3`。两者源码目录都必须干净且处于固定提交。
- Rust 1.93、edition 2024；每个任务结束前在仓库根目录全绿：`cargo fmt --all -- --check`、`cargo clippy --release --all-targets --offline -- -D warnings`、`cargo test --release --offline`、`python3 smoke_test.py ./target/pq-verify-optimized`（需先 `export PQ_OQS_BUILD="$PWD/target/oqs-optimized"`）。
- Python 脚本只用标准库；Shell 脚本兼容 macOS 自带 Bash 3.2。
- `build.sh`、冒烟测试和任何实际计时运行都在普通环境（非沙箱）执行。
- 注释只写“为什么”，不写任务/PR 指针。
- Agent 不操作云主机；阶段三的目标硬件运行由人执行。
- 提交：在功能分支上，scope 用 `bench`，标题 ≤ 72 字符、小写、无句号；不推 `main`，不 force push。

## Review Focus

1. **汇总脚本把不同负载混在一起**（例如 8×8 和 64×16 的同一算法）——预期分成不同行。测试：Task 1 `test_builds_and_workloads_stay_separate`。
2. **BoringSSL 在优化构建里静默退回 `nohw` SHA-256**（CPU 探测失败）——预期和 liboqs 回退一样被门禁拦下。测试：Task 4 `only_generic_backends_count_as_fallback` 新增的 `nohw` 断言，以及冒烟测试的回退分支。
3. **两个库对同一份样本的接受/拒绝不一致**（上下文、域分隔或长度处理不同）——预期所有正例都通过、所有负例都拒绝。测试：Task 3 `boringssl_and_liboqs_verify_each_others_corpora`（双向、覆盖全部 8 个场景）。
4. **`run_formal.sh` 在 macOS Bash 3.2 下不设 `PQ_CPU`**，空数组展开报 `unbound variable`——预期正常运行、不绑核。测试：Task 6 Step 2 在 macOS 上不设 `PQ_CPU` 跑快速模式。
5. **Linux 上链接失败**（缺 `libstdc++` 或静态库顺序问题）——预期 `cargo test` 与冒烟测试在目标机器上照常通过。测试：Task 7 Step 3 在目标机器上执行完整检查。

---

## 阶段一：算法层面对比（可移植构建）

### Task 0: 独立仓库

本工具已从 NewL1 仓库的 `benchmarks/pq-verify` 拆分为独立仓库 [constwz/pq-verify](https://github.com/constwz/pq-verify)，补上了原先从 NewL1 根目录继承的 `rust-toolchain.toml`、`rustfmt.toml`（只保留 stable 选项）和 `clippy.toml`。下文路径都相对于本仓库根目录。仓库要求 GPG 签名，提交由人执行。

---

### Task 0b: 预生成通用样本（`--prepare-only`）

**Files:**
- Modify: `src/main.rs`（`--prepare-only`、`load_corpus` 辅助函数）
- Modify: `src/corpus.rs`（`extended` 改为追加 `0xff`，新增回归测试）
- Modify: `smoke_test.py`、`README.zh-CN.md`、`README.md`

**Interfaces:**
- Produces: `--prepare-only` 只生成并校验样本，向标准输出打印 `sha256sum` 格式清单，不计时、不创建 `--out`、不受回退门禁限制；`fn load_corpus(opts, verifier) -> Result<(PathBuf, Corpus)>` 统一构造样本文件名并加载/生成；`corpus/SHA256SUMS`。
- Consumes（后续任务）：Task 2、5 直接复用 `corpus/`；Task 3 改样本文件名时改 `load_corpus`；Task 6 默认读 `corpus/` 并先核对 `SHA256SUMS`；Task 7 把 `corpus/` 复制到服务器。

- [x] **Step 1: 实现与测试**

- `main.rs`：`--prepare-only` 在内存上限检查之后、回退门禁之前返回；样本加载提取为 `load_corpus`，打印 `Generating`/`Validating` 和耗时。
- `smoke_test.py`：先跑 `--prepare-only`，断言不创建输出目录、清单与文件哈希一致、第二次运行输出相同且不出现 `Generating`、随后的测量运行 `corpus_sha256` 与清单一致。
- 64×16 生成时发现 Falcon-1024 第 573 个样本在 `extended` 下验签通过：PQClean Falcon 接受用零字节补到固定 padded 长度（Falcon-512 为 666 字节，Falcon-1024 为 1280 字节）的签名，原签名恰好短 1 字节时追加 `0x00` 就成了合法签名。`extended` 改为追加 `0xff`，回归测试 `extended_signature_stays_invalid_one_byte_below_falcon_padded_size` 用零字节把 Falcon-512 签名补到 665 字节构造这一情形；改回 `0` 时该测试失败。

- [x] **Step 2: 并行生成全部 17 个参数集（普通环境）**

```bash
mkdir -p corpus && ./target/pq-verify-optimized --list | xargs -P 8 -n 1 \
  ./target/pq-verify-optimized --prepare-only \
  --keys 64 --messages-per-key 16 --message-bytes 32 --corpus-dir corpus \
  --algorithms > corpus/SHA256SUMS
(cd corpus && shasum -a 256 -c SHA256SUMS)
```

macOS 的 BSD `xargs -I` 限制替换后命令不超过 255 字节，所以用 `-n 1` 把算法名追加到末尾。`s` 系列每个签名约 0.5–1 秒，依次生成约 85 分钟，8 路并行约 20 分钟。

---

### Task 1: 跨轮汇总脚本 `summarize.py`

**Files:**
- Create: `summarize.py`
- Create: `test_summarize.py`
- Modify: `README.zh-CN.md`（第 6、7 节）、`README.md`（Outputs、Checks）

**Interfaces:**
- Produces: `summarize.load(directory: Path) -> list[dict]`、`summarize.summarize(rows: list[dict], baseline: str) -> list[dict]`、`summarize.main(argv) -> int`、常量 `summarize.FIELDS`。输出 CSV 列见 `FIELDS`。算法名中 `@` 之前的部分视为参数集（阶段二的 `SLH_DSA_PURE_SHA2_128S@boringssl` 依赖这一点）。

- [x] **Step 1: 写失败的测试**

`test_summarize.py`：

```python
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
```

- [x] **Step 2: 运行，确认失败**

Run: `python3 -m unittest test_summarize -v`
Expected: FAIL，`ModuleNotFoundError: No module named 'summarize'`

- [x] **Step 3: 实现 `summarize.py`**

```python
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
```

- [x] **Step 4: 运行，确认通过**

Run: `python3 -m unittest test_summarize -v`
Expected: 7 个测试全部 `ok`

- [x] **Step 5: 在真实结果上试跑**

Run: `python3 summarize.py results/validation-optimized-cpu | head -3`
Expected: 表头加两行数据，`build` 列为 `optimized`，`hash_backend` 列为空（旧格式结果）。

- [x] **Step 6: 更新 README**

`README.zh-CN.md` 第 6 节末尾（“工具提供原始测量结果，不自动选择跨轮统计模型。”之后）追加：

````markdown
### 跨轮汇总

`summarize.py` 把一个或多个已完成的结果目录合并成一张表，每个（构建、算法、后端、场景、负载）
组合一行。各项取多轮的中位数，并给出 p50 的最小/最大值和 `verify_per_second` 的变异系数
（`verify_per_second_cv`，标准差除以均值）。`throughput_vs_baseline` 是相对基准算法
（默认 ML-DSA-44）的吞吐倍数，只在同一构建、同一场景、同一负载内计算。
没有 `COMPLETE` 的目录，或同一参数集在不同目录中用了不同样本，都会直接报错。

```bash
python3 summarize.py --baseline ML-DSA-44 \
  results/portable-valid-32 results/optimized-valid-32 > results/summary.csv
```
````

第 7 节命令块中 `cargo test --release --offline` 之后加一行 `python3 -m unittest test_summarize`。

`README.md` 在 “This tool emits raw measurements rather than choosing a cross-round statistical model.” 之后追加：

````markdown
`summarize.py` merges one or more finished result directories into one row per
(build, algorithm, backend, case, workload): medians over rounds, the p50 range,
and the coefficient of variation of `verify_per_second`. `throughput_vs_baseline`
is relative to `--baseline` (default ML-DSA-44) within the same build, case and
workload. Directories without `COMPLETE`, or a parameter set measured on different
corpora, are rejected.

```bash
python3 summarize.py --baseline ML-DSA-44 \
  results/portable-valid-32 results/optimized-valid-32 > results/summary.csv
```
````

Checks 命令块中同样追加 `python3 -m unittest test_summarize`。

- [ ] **Step 7: 提交**

```bash
git add summarize.py test_summarize.py \
  README.md README.zh-CN.md
git commit -m "bench: add cross-round summary for pq-verify results"
```

---

### Task 2: 本地出一份算法层面对比（只运行，不改代码）

这一步产出的是开发机上的初步数据，正式数据在 Task 7。

- [x] **Step 1: 构建可移植版本（普通环境）**

Run: `bash build.sh portable`
Expected: 末行 `Built .../target/pq-verify-portable`

- [x] **Step 2: 运行全部参数集的有效签名测试**

```bash
./target/pq-verify-portable \
  --algorithms all --cases valid \
  --keys 64 --messages-per-key 16 --message-bytes 32 \
  --rounds 5 --warmup-ms 3000 --duration-ms 10000 \
  --latency-samples 100000 --latency-max-ms 20000 --seed 42 \
  --corpus-dir corpus --out results/portable-valid-32
```

样本已由 Task 0b 生成，这里只加载并校验（日志全部是 `Validating`，没有 `Generating`）；计时部分约 5 × 8 分钟。
Expected: `results/portable-valid-32/COMPLETE` 存在；`metadata.txt` 中各 `corpus_sha256` 与 `corpus/SHA256SUMS` 一致；`rounds.csv` 中 ML-DSA 的 `backend` 为 `mldsa-native/C`，Falcon 为 `PQClean/clean`。

- [x] **Step 3: 汇总**

Run: `python3 summarize.py --baseline ML-DSA-44 results/portable-valid-32 > results/portable-valid-32/summary.csv`
Expected: 17 行数据；`verify_per_second_cv` 普遍低于 0.05（开发机噪声较大，仅作参考）。

---

## 阶段二：上线成本对比（接入 BoringSSL SLH-DSA-SHA2-128s）

### Task 3: BoringSSL 构建链路与 Verifier 提供者

**Files:**
- Modify: `build.sh`（全文替换）
- Modify: `build.rs`（全文替换）
- Create: `bssl_bridge.cc`
- Create: `src/bssl.rs`
- Modify: `src/oqs.rs`（`Verifier` 结构体、`new`、`keypair`、`sign`、`verify`、`Drop`）
- Modify: `src/corpus.rs:90,209,286,289` 及测试
- Modify: `src/main.rs`（`mod bssl;`、样本文件名）

**Interfaces:**
- Consumes: 无。
- Produces:
  - `bssl::SUFFIX: &str = "@boringssl"`、`bssl::PARAMETER_SET: &str = "SLH_DSA_PURE_SHA2_128S"`、`bssl::PUBLIC_KEY_LEN = 32`、`bssl::SECRET_KEY_LEN = 64`、`bssl::SIGNATURE_LEN = 7856`
  - `bssl::sha256_backend() -> String`，取值 `boringssl-sha256/{hw,avx,ssse3,neon,nohw,c}`
  - `Verifier::new("SLH_DSA_PURE_SHA2_128S@boringssl")` 可用；`Verifier.corpus_name: String`（BoringSSL 为 `SLH_DSA_PURE_SHA2_128S`，liboqs 等于 `name`）
  - `$PQ_OQS_BUILD/boringssl.txt`：`source=`、`build=`、`no_asm=0|1`、`revision=` 四行，由 `build.sh` 写入、`build.rs` 读取

- [ ] **Step 1: 写失败的测试**

在 `src/corpus.rs` 的 `mod tests` 中，把现有测试里两处 `corpus.encode(&name, 32)` / `restored.encode(&name, 32)` 改为 `corpus.encode(&verifier.corpus_name, 32)` / `restored.encode(&verifier.corpus_name, 32)`，并追加：

```rust
    #[test]
    fn boringssl_and_liboqs_verify_each_others_corpora() -> Result<()> {
        oqs::init();
        let liboqs = Verifier::new(crate::bssl::PARAMETER_SET)?;
        let boringssl =
            Verifier::new(&format!("{}{}", crate::bssl::PARAMETER_SET, crate::bssl::SUFFIX))?;
        assert_eq!(boringssl.corpus_name, liboqs.name);
        assert_eq!(boringssl.public_key_len, liboqs.public_key_len);
        assert_eq!(boringssl.signature_max, liboqs.signature_max);
        assert!(boringssl.hash_backend.starts_with("boringssl-sha256/"));
        for (producer, consumer) in [(&liboqs, &boringssl), (&boringssl, &liboqs)] {
            let bytes = Corpus::generate(producer, 2, 2, 32)?.encode(&producer.corpus_name, 32)?;
            // validate() covers every negative case, so both libraries must also agree on rejection.
            Corpus::decode(&bytes, consumer, 2, 2, 32)?.validate(consumer)?;
        }
        assert!(Verifier::new("SLH_DSA_PURE_SHAKE_256F@boringssl").is_err());
        Ok(())
    }
```

- [ ] **Step 2: 运行，确认失败**

Run: `export PQ_OQS_BUILD="$PWD/target/oqs-optimized" && cargo test --release --offline corpus::tests`
Expected: 编译失败，`no field corpus_name on type Verifier` 和 `could not find bssl in the crate root`

- [ ] **Step 3: 替换 `build.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
revision=5a1a854b0dc9f2141bdc771c555ee60c37950183 # liboqs 0.16.0
bssl_revision=af41e135bc1714981fb8a791e9dda4fc6ff140c3 # BoringSSL main, 2026-10-21
mode=${1:-optimized}
case "$mode" in
  optimized) dist=ON; bssl_no_asm=0 ;;
  portable) dist=OFF; bssl_no_asm=1 ;;
  *) echo "usage: $0 [optimized|portable]" >&2; exit 2 ;;
esac
cmake_args=(-DOQS_DIST_BUILD="$dist")
if [[ "$mode" == portable ]]; then
  # liboqs's generic ARM target still detects NEON/crypto extensions by default.
  for extension in ADX AES AVX AVX2 AVX512 AVX512BW AVX512DQ AVX512F \
      VPCLMULQDQ BMI1 BMI2 FMA PCLMULQDQ POPCNT SSE SSE2 SSE3 \
      ARM_AES ARM_SHA2 ARM_SHA3 ARM_NEON; do
    cmake_args+=("-DOQS_USE_${extension}_INSTRUCTIONS=OFF")
  done
fi
source_dir=${PQ_OQS_SOURCE:-"$root/target/liboqs-source"}
build_dir="$root/target/oqs-$mode"
mkdir -p "$root/target"
if [[ ! -d "$source_dir" ]]; then
  git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git "$source_dir"
fi
[[ $(git -C "$source_dir" rev-parse HEAD) == "$revision" ]] || {
  echo "liboqs must be pinned to $revision" >&2; exit 1;
}
[[ -z $(git -C "$source_dir" status --porcelain) ]] || {
  echo "liboqs source must be clean" >&2; exit 1;
}
algorithms='SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_falcon_512;SIG_falcon_1024'
for hash in sha2 shake; do
  for level in 128 192 256; do
    for variant in s f; do
      algorithms+=";SIG_slh_dsa_pure_${hash}_${level}${variant}"
    done
  done
done
# Cached conditional backend options otherwise survive changes in CPU switches.
cmake --fresh -S "$source_dir" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
  -DOQS_OPT_TARGET=generic -DOQS_MINIMAL_BUILD="$algorithms" "${cmake_args[@]}"
if [[ "$mode" == portable ]] && \
    grep -Eq '^#define OQS_ENABLE_SIG_(ml_dsa_.*_(x86_64|aarch64)|falcon_.*_(avx2|aarch64)) ' \
    "$build_dir/include/oqs/oqsconfig.h"; then
  echo "portable build unexpectedly enabled an optimized signature backend" >&2
  exit 1
fi
cmake --build "$build_dir" --parallel "${PQ_BUILD_JOBS:-4}"

bssl_source=${PQ_BSSL_SOURCE:-"$root/target/boringssl-source"}
bssl_build="$root/target/bssl-$mode"
if [[ ! -d "$bssl_source" ]]; then
  git init -q "$bssl_source"
  git -C "$bssl_source" fetch -q --depth 1 https://github.com/google/boringssl.git "$bssl_revision"
  git -C "$bssl_source" checkout -q FETCH_HEAD
fi
[[ $(git -C "$bssl_source" rev-parse HEAD) == "$bssl_revision" ]] || {
  echo "BoringSSL must be pinned to $bssl_revision" >&2; exit 1;
}
[[ -z $(git -C "$bssl_source" status --porcelain) ]] || {
  echo "BoringSSL source must be clean" >&2; exit 1;
}
bssl_args=(-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF)
if [[ $bssl_no_asm == 1 ]]; then
  # Portable mode: C SHA-256 only, matching liboqs's disabled CPU extensions.
  bssl_args+=(-DOPENSSL_NO_ASM=1)
fi
CC=${CC:-cc} CXX=${CXX:-c++} cmake --fresh -S "$bssl_source" -B "$bssl_build" "${bssl_args[@]}"
cmake --build "$bssl_build" --target crypto --parallel "${PQ_BUILD_JOBS:-4}"
printf 'source=%s\nbuild=%s\nno_asm=%s\nrevision=%s\n' \
  "$bssl_source" "$bssl_build" "$bssl_no_asm" "$bssl_revision" > "$build_dir/boringssl.txt"

{
  echo "liboqs_revision=$revision"
  echo "mode=$mode"
  echo "openssl=OFF"
  echo "dispatch=$dist"
  echo "source=$source_dir"
  echo "build=$build_dir"
  git -C "$source_dir" log -1 --format='commit_date=%cI'
  cat "$build_dir/CMakeCache.txt"
  echo "boringssl_revision=$bssl_revision"
  echo "boringssl_no_asm=$bssl_no_asm"
  cat "$bssl_build/CMakeCache.txt"
} > "$build_dir/provenance.txt"
CARGO_TARGET_DIR="$root/target" PQ_OQS_BUILD="$build_dir" \
  cargo build --manifest-path "$root/Cargo.toml" --release --offline
cp "$root/target/release/pq-verify-bench" "$root/target/pq-verify-$mode"
echo "Built $root/target/pq-verify-$mode" >&2
```

- [ ] **Step 4: 新建 `bssl_bridge.cc`**

```cpp
// Reads BoringSSL's SHA-256 block dispatch through its pinned internal headers.
// Must mirror sha256_block_data_order in crypto/fipsmodule/sha/sha256.cc.inc.
#include "crypto/fipsmodule/sha/internal.h"

extern "C" const char *pq_bssl_sha256_backend(void) {
#if defined(OPENSSL_NO_ASM)
  return "boringssl-sha256/c";
#else
#if defined(SHA256_ASM_HW)
  if (bssl::sha256_hw_capable()) return "boringssl-sha256/hw";
#endif
#if defined(SHA256_ASM_AVX)
  if (bssl::sha256_avx_capable()) return "boringssl-sha256/avx";
#endif
#if defined(SHA256_ASM_SSSE3)
  if (bssl::sha256_ssse3_capable()) return "boringssl-sha256/ssse3";
#endif
#if defined(SHA256_ASM_NEON)
  if (bssl::CRYPTO_is_NEON_capable()) return "boringssl-sha256/neon";
#endif
  return "boringssl-sha256/nohw";
#endif
}
```

- [ ] **Step 5: 替换 `build.rs`**

```rust
//! Links separately built, pinned liboqs and BoringSSL without downloading during Cargo builds.

use std::{env, fs, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    let status = command.status().expect("could not start native build command");
    assert!(status.success(), "native build failed: {command:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=native.c");
    println!("cargo:rerun-if-changed=bssl_bridge.cc");
    for name in ["PQ_OQS_BUILD", "CC", "CXX", "AR"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let root = PathBuf::from(env::var_os("PQ_OQS_BUILD").expect("run ./build.sh first"));
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    for file in ["lib/liboqs.a", "include/oqs/oqsconfig.h", "provenance.txt", "boringssl.txt"] {
        println!("cargo:rerun-if-changed={}", root.join(file).display());
    }
    let bssl = fs::read_to_string(root.join("boringssl.txt")).expect("run ./build.sh first");
    let field = |key: &str| {
        bssl.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("boringssl.txt has no {key}"))
            .to_owned()
    };
    let bssl_source = PathBuf::from(field("source"));
    let bssl_lib = PathBuf::from(field("build")).join("libcrypto.a");
    println!("cargo:rerun-if-changed={}", bssl_lib.display());
    assert_eq!(env::var("HOST"), env::var("TARGET"), "native builds only");
    run(Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args(["-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(root.join("include"))
        .args(["-c", "native.c", "-o"])
        .arg(out.join("native.o")));
    let mut bridge = Command::new(env::var_os("CXX").unwrap_or_else(|| "c++".into()));
    // -isystem: BoringSSL's internal headers are not -Wextra clean.
    bridge
        .args(["-std=c++17", "-O3", "-Wall", "-Wextra", "-Werror", "-isystem"])
        .arg(bssl_source.join("include"))
        .arg("-isystem")
        .arg(&bssl_source);
    if field("no_asm") == "1" {
        // Must match the library build, or the bridge reports asm paths that were not built.
        bridge.arg("-DOPENSSL_NO_ASM");
    }
    run(bridge.args(["-c", "bssl_bridge.cc", "-o"]).arg(out.join("bssl_bridge.o")));
    run(Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
        .arg("crs")
        .arg(out.join("libpq_bridge.a"))
        .arg(out.join("native.o"))
        .arg(out.join("bssl_bridge.o")));
    // Renamed copy: `-l crypto` could otherwise resolve to a system OpenSSL.
    fs::copy(&bssl_lib, out.join("libpq_boringssl.a")).expect("copy BoringSSL libcrypto.a");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", root.join("lib").display());
    println!("cargo:rustc-link-lib=static=pq_bridge");
    println!("cargo:rustc-link-lib=static=oqs");
    println!("cargo:rustc-link-lib=static=pq_boringssl");
    // BoringSSL's libcrypto is C++ and needs the platform C++ runtime.
    let cxx_runtime =
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") { "c++" } else { "stdc++" };
    println!("cargo:rustc-link-lib={cxx_runtime}");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-env=PQ_BUILD_PROVENANCE={}", root.join("provenance.txt").display());
    println!("cargo:rustc-env=PQ_BUILD_CONFIG={}", root.join("include/oqs/oqsconfig.h").display());
    println!("cargo:rustc-env=PQ_BSSL_REVISION={}", field("revision"));
    let rustc = Command::new(env::var_os("RUSTC").unwrap()).arg("--version").output().unwrap();
    println!("cargo:rustc-env=PQ_RUSTC={}", String::from_utf8_lossy(&rustc.stdout).trim());
    println!(
        "cargo:rustc-env=PQ_RUSTFLAGS={}",
        env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default().replace('\x1f', " ")
    );
}
```

- [ ] **Step 6: 新建 `src/bssl.rs`**

```rust
//! BoringSSL SLH-DSA-SHA2-128s (FIPS 205 pure, empty context): a hardware-SHA-256
//! implementation measured on the same corpus as liboqs's parameter set.

use std::ffi::{CStr, c_char, c_int};

/// Suffix that selects BoringSSL for a liboqs parameter-set name.
pub(crate) const SUFFIX: &str = "@boringssl";
/// Only parameter set where BoringSSL adds a faster implementation; its SHAKE
/// variant uses portable Keccak and is slower than liboqs.
pub(crate) const PARAMETER_SET: &str = "SLH_DSA_PURE_SHA2_128S";
pub(crate) const PUBLIC_KEY_LEN: usize = 32;
pub(crate) const SECRET_KEY_LEN: usize = 64;
pub(crate) const SIGNATURE_LEN: usize = 7856;

unsafe extern "C" {
    fn SLHDSA_SHA2_128S_generate_key(public_key: *mut u8, private_key: *mut u8);
    fn SLHDSA_SHA2_128S_sign(
        signature: *mut u8,
        private_key: *const u8,
        msg: *const u8,
        msg_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> c_int;
    fn SLHDSA_SHA2_128S_verify(
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
        msg: *const u8,
        msg_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> c_int;
    fn pq_bssl_sha256_backend() -> *const c_char;
}

pub(crate) fn sha256_backend() -> String {
    // SAFETY: returns a pointer to a static NUL-terminated string literal.
    unsafe { CStr::from_ptr(pq_bssl_sha256_backend()) }.to_string_lossy().into_owned()
}

pub(crate) fn keypair(public_key: &mut [u8], private_key: &mut [u8]) {
    assert_eq!((public_key.len(), private_key.len()), (PUBLIC_KEY_LEN, SECRET_KEY_LEN));
    // SAFETY: both buffers have exactly the fixed lengths the API writes.
    unsafe { SLHDSA_SHA2_128S_generate_key(public_key.as_mut_ptr(), private_key.as_mut_ptr()) };
}

pub(crate) fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> bool {
    assert_eq!((private_key.len(), signature.len()), (SECRET_KEY_LEN, SIGNATURE_LEN));
    // SAFETY: fixed-size key and output buffers; the message has an explicit length;
    // a null context with length 0 is the documented empty context.
    unsafe {
        SLHDSA_SHA2_128S_sign(
            signature.as_mut_ptr(),
            private_key.as_ptr(),
            message.as_ptr(),
            message.len(),
            std::ptr::null(),
            0,
        ) == 1
    }
}

pub(crate) fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    assert_eq!(public_key.len(), PUBLIC_KEY_LEN);
    // SAFETY: the public key has the fixed length; message and signature carry
    // explicit lengths; a null context with length 0 is the empty context.
    unsafe {
        SLHDSA_SHA2_128S_verify(
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
            message.as_ptr(),
            message.len(),
            std::ptr::null(),
            0,
        ) == 1
    }
}
```

- [ ] **Step 7: 修改 `src/oqs.rs`**

1. `use crate::Result;` 改为 `use crate::{Result, bssl};`
2. 结构体 `Verifier` 中把 `handle: NonNull<c_void>,` 替换为下面两行，并在 `name` 之后加 `corpus_name`：

```rust
pub(crate) struct Verifier {
    provider: Provider,
    pub(crate) name: String,
    /// Parameter set whose corpus this verifier reads; shared across providers.
    pub(crate) corpus_name: String,
    pub(crate) public_key_len: usize,
    secret_key_len: usize,
    pub(crate) signature_max: usize,
    pub(crate) category: u32,
    pub(crate) version: String,
    pub(crate) backend: String,
    pub(crate) hash_backend: String,
}

#[derive(Clone, Copy)]
enum Provider {
    Oqs(NonNull<c_void>),
    BoringSsl,
}
```

3. `Verifier::new` 整体替换为：

```rust
    pub(crate) fn new(name: &str) -> Result<Self> {
        if let Some(parameter_set) = name.strip_suffix(bssl::SUFFIX) {
            if parameter_set != bssl::PARAMETER_SET {
                return Err(format!("algorithm unavailable: {name}").into());
            }
            return Ok(Self {
                provider: Provider::BoringSsl,
                name: name.to_owned(),
                corpus_name: parameter_set.to_owned(),
                public_key_len: bssl::PUBLIC_KEY_LEN,
                secret_key_len: bssl::SECRET_KEY_LEN,
                signature_max: bssl::SIGNATURE_LEN,
                category: 1,
                version: concat!("boringssl ", env!("PQ_BSSL_REVISION")).to_owned(),
                backend: "boringssl/slhdsa".to_owned(),
                hash_backend: bssl::sha256_backend(),
            });
        }
        let c_name = CString::new(name)?;
        // SAFETY: name is NUL-terminated; null signals an unavailable algorithm.
        let handle = NonNull::new(unsafe { OQS_SIG_new(c_name.as_ptr()) })
            .ok_or_else(|| format!("algorithm unavailable: {name}"))?;
        // SAFETY: all accessors receive the live OQS_SIG allocated above.
        unsafe {
            Ok(Self {
                provider: Provider::Oqs(handle),
                name: name.to_owned(),
                corpus_name: name.to_owned(),
                public_key_len: pq_public_key_len(handle.as_ptr()),
                secret_key_len: pq_secret_key_len(handle.as_ptr()),
                signature_max: pq_signature_len(handle.as_ptr()),
                category: pq_category(handle.as_ptr()),
                version: CStr::from_ptr(pq_algorithm_version(handle.as_ptr()))
                    .to_string_lossy()
                    .into_owned(),
                backend: CStr::from_ptr(pq_backend(handle.as_ptr())).to_string_lossy().into_owned(),
                hash_backend: if name.starts_with("SLH_DSA") {
                    "slhdsa-c/internal".to_owned()
                } else {
                    CStr::from_ptr(pq_sha3_backend()).to_string_lossy().into_owned()
                },
            })
        }
    }
```

4. `keypair`、`sign`、`verify` 改为按提供者分派：

```rust
    pub(crate) fn keypair(&self) -> Result<(Vec<u8>, SecretKey)> {
        let mut pk = vec![0; self.public_key_len];
        let mut sk = SecretKey(vec![0; self.secret_key_len]);
        match self.provider {
            Provider::Oqs(handle) => {
                // SAFETY: both output buffers have the lengths advertised by this OQS_SIG.
                let status =
                    unsafe { OQS_SIG_keypair(handle.as_ptr(), pk.as_mut_ptr(), sk.0.as_mut_ptr()) };
                if status != 0 {
                    return Err(format!("{} key generation failed: {status}", self.name).into());
                }
            }
            Provider::BoringSsl => bssl::keypair(&mut pk, &mut sk.0),
        }
        Ok((pk, sk))
    }

    pub(crate) fn sign(&self, sk: &SecretKey, message: &[u8]) -> Result<Vec<u8>> {
        if sk.0.len() != self.secret_key_len {
            return Err("wrong secret key length".into());
        }
        let mut signature = vec![0; self.signature_max];
        let len = match self.provider {
            Provider::Oqs(handle) => {
                let mut len = signature.len();
                // SAFETY: inputs are readable for their lengths, output has maximum signature capacity.
                let status = unsafe {
                    OQS_SIG_sign(
                        handle.as_ptr(),
                        signature.as_mut_ptr(),
                        &mut len,
                        message.as_ptr(),
                        message.len(),
                        sk.0.as_ptr(),
                    )
                };
                if status != 0 {
                    return Err(format!("{} signing failed: {status}", self.name).into());
                }
                len
            }
            Provider::BoringSsl => {
                if !bssl::sign(&sk.0, message, &mut signature) {
                    return Err(format!("{} signing failed", self.name).into());
                }
                signature.len()
            }
        };
        if len == 0 || len > signature.len() {
            return Err(format!("{} signing failed: length={len}", self.name).into());
        }
        signature.truncate(len);
        Ok(signature)
    }

    pub(crate) fn verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Neither API takes a public-key length; never pass a short key.
        assert_eq!(pk.len(), self.public_key_len);
        match self.provider {
            Provider::Oqs(handle) => {
                // SAFETY: pk has exactly the required size; message/signature have explicit lengths.
                unsafe {
                    OQS_SIG_verify(
                        handle.as_ptr(),
                        message.as_ptr(),
                        message.len(),
                        signature.as_ptr(),
                        signature.len(),
                        pk.as_ptr(),
                    ) == 0
                }
            }
            Provider::BoringSsl => bssl::verify(pk, message, signature),
        }
    }
```

5. `impl Drop for Verifier` 改为只释放 liboqs 句柄：

```rust
impl Drop for Verifier {
    fn drop(&mut self) {
        if let Provider::Oqs(handle) = self.provider {
            // SAFETY: this object uniquely owns the handle and releases it exactly once.
            unsafe { OQS_SIG_free(handle.as_ptr()) };
        }
    }
}
```

- [ ] **Step 8: 修改 `src/corpus.rs` 与 `src/main.rs`**

`src/corpus.rs`：
- 第 90 行 `corpus.encode(&verifier.name, message_bytes)?` → `corpus.encode(&verifier.corpus_name, message_bytes)?`
- 第 209 行 `!= verifier.name.as_bytes()` → `!= verifier.corpus_name.as_bytes()`

`src/main.rs`：
- 在 `mod corpus;` 之前加 `mod bssl;`
- `load_corpus` 中样本文件名的 `verifier.name` → `verifier.corpus_name`（日志里的 `verifier.name` 不变）：

```rust
    let file = opts.corpus_dir.join(format!(
        "{}-k{}-n{}-m{}.bin",
        verifier.corpus_name, opts.keys, opts.messages_per_key, opts.message_bytes
    ));
```

`--prepare-only` 因此对 `@boringssl` 打印的是共用的 `SLH_DSA_PURE_SHA2_128S-...bin`，与 liboqs 那一行相同；`sha256sum -c` 对重复行没有影响。

- [ ] **Step 9: 构建并运行测试（普通环境）**

```bash
bash build.sh optimized
export PQ_OQS_BUILD="$PWD/target/oqs-optimized"
cargo test --release --offline
```

Expected: 首次会拉取 BoringSSL（约 1–4 分钟）并编译（约 30 秒）；测试全部通过，包括 `boringssl_and_liboqs_verify_each_others_corpora`。

- [ ] **Step 10: fmt / clippy / 冒烟**

```bash
cargo fmt --all -- --check
cargo clippy --release --all-targets --offline -- -D warnings
python3 smoke_test.py ./target/pq-verify-optimized
```

Expected: 全部通过。冒烟测试此时仍是 17 个参数集（BoringSSL 尚未加入 `--algorithms all`）。

- [ ] **Step 11: 提交**

```bash
git add build.sh build.rs bssl_bridge.cc \
  src
git commit -m "bench: add BoringSSL SLH-DSA-SHA2-128s verifier provider" \
  -m "Same FIPS 205 corpus as liboqs, hardware SHA-256; interop checked both ways."
```

---

### Task 4: 在 CLI、回退门禁、冒烟测试和 README 中暴露 BoringSSL

**Files:**
- Modify: `src/main.rs`（`all_algorithms`、`HELP`、回退门禁、测试）
- Modify: `src/oqs.rs`（`is_fallback_backend` → `is_fallback`，测试）
- Modify: `smoke_test.py`
- Modify: `README.zh-CN.md`、`README.md`

**Interfaces:**
- Consumes: Task 3 的 `bssl::PARAMETER_SET`、`bssl::SUFFIX`、`Verifier.hash_backend`。
- Produces: `oqs::is_fallback(backend: &str, hash_backend: &str) -> bool`；`--algorithms all` 共 18 项，`tier1` 共 7 项（含 `SLH_DSA_PURE_SHA2_128S@boringssl`）。

- [ ] **Step 1: 写失败的测试**

`src/oqs.rs` 的测试整体替换为：

```rust
    #[test]
    fn only_generic_backends_count_as_fallback() {
        for (backend, hash) in [
            ("mldsa-native/C", "xkcp/plain64"),
            ("PQClean/clean", "xkcp/avx2"),
            ("boringssl/slhdsa", "boringssl-sha256/nohw"),
        ] {
            assert!(is_fallback(backend, hash), "{backend} {hash}");
        }
        for (backend, hash) in [
            ("mldsa-native/x86_64", "xkcp/avx2"),
            ("mldsa-native/aarch64", "xkcp/plain64"),
            ("PQClean/avx2", "xkcp/avx2"),
            ("PQClean/aarch64", "xkcp/plain64"),
            ("slhdsa-c/portable", "slhdsa-c/internal"),
            ("boringssl/slhdsa", "boringssl-sha256/hw"),
            ("boringssl/slhdsa", "boringssl-sha256/avx"),
            ("boringssl/slhdsa", "boringssl-sha256/c"),
        ] {
            assert!(!is_fallback(backend, hash), "{backend} {hash}");
        }
    }
```

`src/main.rs` 的测试中，把开头两行改为：

```rust
        assert_eq!(all_algorithms().len(), 18);
        assert_eq!(tier1().len(), 7);
        assert!(tier1().contains(&"SLH_DSA_PURE_SHA2_128S@boringssl".to_owned()));
```

并在非法参数列表中加一项 `vec!["--algorithms", "SLH_DSA_PURE_SHAKE_256F@boringssl"],`。

- [ ] **Step 2: 运行，确认失败**

Run: `cargo test --release --offline`
Expected: 编译失败 `cannot find function is_fallback`；修好编译后 `all_algorithms().len()` 断言失败（17 != 18）

- [ ] **Step 3: 实现**

`src/oqs.rs`：把 `is_fallback_backend` 整个替换为：

```rust
/// Backends that a dispatching build selects only when CPU feature detection
/// fails or the CPU lacks the required extensions. slhdsa-c is excluded: this
/// liboqs pin has no other SLH-DSA backend.
pub(crate) fn is_fallback(backend: &str, hash_backend: &str) -> bool {
    matches!(backend, "mldsa-native/C" | "PQClean/clean")
        || hash_backend == "boringssl-sha256/nohw"
}
```

`src/main.rs`：
- `all_algorithms()` 在 `names` 返回前加：

```rust
    names.push(format!("{}{}", bssl::PARAMETER_SET, bssl::SUFFIX));
```

- 回退门禁改为：

```rust
    if dist_build
        && !opts.allow_fallback
        && let Some(v) = verifiers.iter().find(|v| oqs::is_fallback(&v.backend, &v.hash_backend))
    {
        return Err(format!(
            "{} dispatched to {} / {} in a runtime-dispatch build: CPU feature detection \
             is blocked (e.g. sandboxed sysctl) or the CPU lacks the extensions. \
             Run where detection works, or pass --allow-fallback to record it anyway",
            v.name, v.backend, v.hash_backend
        )
        .into());
    }
```

- `HELP` 中 `default: tier1 (6 parameter sets)` → `default: tier1 (7 entries)`；`--list ... list all 17 supported parameter sets` → `list all 18 entries (17 liboqs + SLH_DSA_PURE_SHA2_128S@boringssl)`；`--allow-fallback` 说明的 `C for ML-DSA/Falcon` → `C for ML-DSA/Falcon or nohw SHA-256 for BoringSSL`。

- [ ] **Step 4: 更新冒烟测试 `smoke_test.py`**

- `CASES = 8` 之后加 `ALGORITHMS = 18`；`assert len(rows) == 17 * CASES * 2` → `assert len(rows) == ALGORITHMS * CASES * 2`。
- 样本路径改为按参数集取文件：

```python
            parameter_set = row["algorithm"].split("@")[0]
            corpus = root / "corpus" / f"{parameter_set}-k2-n1-m32.bin"
```

- 在 `for row in rows:` 循环之后加：

```python
        assert hashes["SLH_DSA_PURE_SHA2_128S@boringssl"] == hashes["SLH_DSA_PURE_SHA2_128S"]
```

- `fell_back` 判断改为：

```python
        fell_back = "dist_build=true" in metadata and any(
            row["backend"] in FALLBACK_BACKENDS or row["hash_backend"] == "boringssl-sha256/nohw"
            for row in rows
        )
```

- 最后的 `print` 中 `17 algorithms` → `{ALGORITHMS} algorithms`。

- [ ] **Step 5: 更新 README**

`README.zh-CN.md`：
- 开头第一段末尾加：“SLH-DSA-SHA2-128s 另用 BoringSSL（固定提交 `af41e135bc1714981fb8a791e9dda4fc6ff140c3`）测一份，作为使用硬件 SHA-256 的对照实现。”
- 第 1 节依赖中 “C 编译器” → “C11 和 C++17 编译器”；“`--list` 列出支持的全部 17 个参数集” → “`--list` 列出全部 18 项（17 个 liboqs 参数集，加 `SLH_DSA_PURE_SHA2_128S@boringssl`）”。
- 第 2 节表格 `tier1` 行改为 “ML-DSA-44；Falcon-512；SLH-DSA 的 SHA2/SHAKE × 128s/128f；`SLH_DSA_PURE_SHA2_128S@boringssl`，共 7 项”，`all` 行补 “，加 BoringSSL 实现，共 18 项”。
- 第 4 节“跨算法族比较时，SLH-DSA 处于明显劣势”一段之后追加：

```markdown
**怎样得到公平对比。** 比较算法本身，用可移植构建：三个算法族都是纯 C，BoringSSL 也以
`OPENSSL_NO_ASM` 构建。比较上线成本，用优化构建中的 `SLH_DSA_PURE_SHA2_128S@boringssl`：
它使用 SHA-256 硬件指令，与 liboqs 的 `SLH_DSA_PURE_SHA2_128S` 共用同一份样本文件，
每次运行开始时会用 BoringSSL 重新校验全部正例和负例，两个库判定不一致时直接报错。
在 Apple M 系列开发机上，它的验签耗时约为 liboqs 同参数集的 1/6。BoringSSL 的
SHAKE-256f 同样是纯 C Keccak，实测比 liboqs 慢约 15%，因此没有接入。
```

- 第 6 节字段表 `hash_backend` 一行改为：“ML-DSA/Falcon 使用的 liboqs Keccak 实现；liboqs SLH-DSA 为 `slhdsa-c/internal`；BoringSSL 为 `boringssl-sha256/{hw,avx,ssse3,neon,nohw,c}`”。
- 第 7 节测试覆盖说明加 “BoringSSL 与 liboqs 双向互验样本”；冒烟测试 “17 个参数集 × 8 个场景” → “18 项 × 8 个场景”。

`README.md` 做对应修改，第 4 节追加段落：

```markdown
**Getting a fair comparison.** For the algorithms themselves, compare portable
builds: all three families are plain C, and BoringSSL is built with
`OPENSSL_NO_ASM`. For deployment cost, use `SLH_DSA_PURE_SHA2_128S@boringssl` in
the optimized build: it uses hardware SHA-256, shares the corpus file of liboqs's
`SLH_DSA_PURE_SHA2_128S`, and revalidates every positive and negative sample with
BoringSSL before timing, failing if the libraries disagree. On an Apple M-series
development machine it verifies in about 1/6 of liboqs's time. BoringSSL's
SHAKE-256f also uses portable Keccak and measured about 15% slower than liboqs, so
it is not included.
```

- [ ] **Step 6: 构建并跑全部检查（普通环境）**

```bash
bash build.sh optimized && bash build.sh portable
export PQ_OQS_BUILD="$PWD/target/oqs-optimized"
cargo fmt --all -- --check
cargo clippy --release --all-targets --offline -- -D warnings
cargo test --release --offline
python3 -m unittest test_summarize
python3 smoke_test.py ./target/pq-verify-optimized
```

Expected: 全部通过；冒烟测试输出 `PASS: 18 algorithms × 8 cases × 2 rounds ... (native dispatch)`。

- [ ] **Step 7: 确认可移植构建的标签**

```bash
./target/pq-verify-portable --algorithms SLH_DSA_PURE_SHA2_128S@boringssl --keys 2 --messages-per-key 1 \
  --rounds 1 --warmup-ms 1 --duration-ms 10 --latency-samples 10 --out results/bssl-portable-check
cut -d, -f1-3 results/bssl-portable-check/rounds.csv && rm -rf results/bssl-portable-check
```

Expected: `SLH_DSA_PURE_SHA2_128S@boringssl,boringssl/slhdsa,boringssl-sha256/c`

- [ ] **Step 8: 提交**

```bash
git add -A
git commit -m "bench: expose BoringSSL SLH-DSA in pq-verify CLI and docs"
```

---

### Task 5: 本地出一份上线成本对比（只运行，不改代码）

- [ ] **Step 1: 优化构建跑全部参数集的有效签名（复用 Task 2 的样本）**

```bash
./target/pq-verify-optimized \
  --algorithms all --cases valid \
  --keys 64 --messages-per-key 16 --message-bytes 32 \
  --rounds 5 --warmup-ms 3000 --duration-ms 10000 \
  --latency-samples 100000 --latency-max-ms 20000 --seed 42 \
  --corpus-dir corpus --out results/optimized-valid-32
```

Expected: 约 40 分钟；`COMPLETE` 存在；`SLH_DSA_PURE_SHA2_128S@boringssl` 行 `hash_backend` 为 `boringssl-sha256/hw`。

- [ ] **Step 2: 两份结果一起汇总**

Run: `python3 summarize.py --baseline ML-DSA-44 results/portable-valid-32 results/optimized-valid-32 > results/fairness-local.csv`
Expected: 退出码 0（说明两次运行用的是同一份样本）。

- [ ] **Step 3: 合理性检查**

Run: `grep -E '^optimized,SLH_DSA_PURE_SHA2_128S' results/fairness-local.csv | cut -d, -f1,2,4,10`（第 10 列是 `p50_median_ns`）
Expected: `@boringssl` 行的 `p50_median_ns` 约为 liboqs 行的 1/6（spike 中约 81 µs 对 475 µs）；低于 3 倍时先检查 `hash_backend`。

---

## 阶段三：目标硬件正式测试

### Task 6: 正式测试脚本 `run_formal.sh`

**Files:**
- Create: `run_formal.sh`
- Modify: `README.zh-CN.md`（第 4 节末尾）、`README.md`（Formal measurements 末尾）

**Interfaces:**
- Consumes: `target/pq-verify-optimized`、`target/pq-verify-portable`（都必须是 Task 4 之后的构建）、`summarize.py`。
- Consumes: Task 0b 生成的 `corpus/SHA256SUMS`（或 `PQ_CORPUS_DIR`）；正式模式缺少清单或核对失败时，在创建 `OUTPUT_DIR` 之前退出。
- Produces: `OUTPUT_DIR/{host.txt,corpus.SHA256SUMS,optimized-valid/,optimized-wrong-message+wrong-key/,optimized-corrupt-head+corrupt-mid+corrupt-tail+truncated+extended/,portable-valid/,summary.csv}`

- [ ] **Step 1: 写脚本**

```bash
#!/usr/bin/env bash
# Formal layer-A run: optimized valid and negative groups, portable valid, then a
# cross-round summary. PQ_CPU pins every run to one CPU (Linux taskset);
# PQ_FORMAL_QUICK=1 swaps in seconds-long settings to check the pipeline only.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
out=${1:?usage: $0 OUTPUT_DIR}
[[ ! -e "$out" ]] || { echo "$out already exists" >&2; exit 1; }
for mode in optimized portable; do
  [[ -x "$root/target/pq-verify-$mode" ]] || { echo "missing binary: bash build.sh $mode" >&2; exit 1; }
done

if [[ ${PQ_FORMAL_QUICK:-0} == 1 ]]; then
  corpus=$out/corpus
  workload=(--keys 2 --messages-per-key 2)
  valid=(--rounds 2 --warmup-ms 1 --duration-ms 5 --latency-samples 20 --latency-max-ms 50)
  negative=("${valid[@]}")
else
  # Pre-generated with --prepare-only and copied between hosts: re-signing here
  # would add over an hour and change the inputs.
  corpus=${PQ_CORPUS_DIR:-$root/corpus}
  [[ -f "$corpus/SHA256SUMS" ]] || {
    echo "missing $corpus/SHA256SUMS: generate it with --prepare-only (README)" >&2; exit 1;
  }
  if command -v sha256sum > /dev/null; then check=(sha256sum); else check=(shasum -a 256); fi
  (cd "$corpus" && "${check[@]}" -c --quiet SHA256SUMS)
  workload=(--keys 64 --messages-per-key 16)
  valid=(--rounds 10 --warmup-ms 3000 --duration-ms 10000 --latency-samples 100000 --latency-max-ms 20000)
  # Fewer rounds and a shorter cap: negative groups have 2-5x more jobs than valid.
  negative=(--rounds 5 --warmup-ms 3000 --duration-ms 10000 --latency-samples 100000 --latency-max-ms 10000)
fi
pin=()
if [[ -n ${PQ_CPU:-} ]]; then
  pin=(taskset -c "$PQ_CPU")
fi

mkdir -p "$out"
{
  date -u +%Y-%m-%dT%H:%M:%SZ
  uname -a
  if [[ -r /proc/cpuinfo ]]; then
    grep -m1 'model name' /proc/cpuinfo || true   # absent on ARM Linux
    echo "flags: $(grep -o -w -E 'avx2|avx512f|bmi2|sha_ni' /proc/cpuinfo | sort -u | tr '\n' ' ')"
    cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c || true
  fi
  echo "PQ_CPU=${PQ_CPU:-unpinned} PQ_FORMAL_QUICK=${PQ_FORMAL_QUICK:-0} corpus=$corpus"
} > "$out/host.txt"
[[ ! -f "$corpus/SHA256SUMS" ]] || cp "$corpus/SHA256SUMS" "$out/corpus.SHA256SUMS"

measure() {
  local mode=$1 cases=$2
  shift 2
  echo "== $mode: $cases" >&2
  # ${pin[@]+...}: Bash 3.2 treats an empty array as unbound under set -u.
  ${pin[@]+"${pin[@]}"} "$root/target/pq-verify-$mode" --algorithms all --cases "$cases" \
    --message-bytes 32 --seed 42 "${workload[@]}" "$@" \
    --corpus-dir "$corpus" --out "$out/$mode-${cases//,/+}"
}
measure optimized valid "${valid[@]}"
measure optimized wrong-message,wrong-key "${negative[@]}"
measure optimized corrupt-head,corrupt-mid,corrupt-tail,truncated,extended "${negative[@]}"
measure portable valid "${valid[@]}"
python3 "$root/summarize.py" --baseline ML-DSA-44 "$out"/optimized-* "$out"/portable-* \
  > "$out/summary.csv"
echo "Summary: $out/summary.csv" >&2
```

- [ ] **Step 2: 在 macOS 上不设 `PQ_CPU` 跑快速模式（普通环境）**

```bash
PQ_FORMAL_QUICK=1 bash run_formal.sh results/formal-quick
awk -F, 'NR > 1 { print $1 }' results/formal-quick/summary.csv | sort | uniq -c
```

Expected: 没有 `unbound variable` 报错；输出 `144 optimized` 和 `18 portable`（18 项 × 8 场景，加 18 项 × 1 场景）。

- [ ] **Step 3: 确认不会覆盖已有结果**

Run: `PQ_FORMAL_QUICK=1 bash run_formal.sh results/formal-quick; echo "exit=$?"`
Expected: `results/formal-quick already exists`，`exit=1`。然后 `rm -rf results/formal-quick`。

Run: `PQ_CORPUS_DIR=$(mktemp -d) bash run_formal.sh results/formal-nocorpus; echo "exit=$?"; ls -d results/formal-nocorpus`
Expected: `missing .../SHA256SUMS`，`exit=1`，`results/formal-nocorpus` 不存在。

- [ ] **Step 4: 更新 README**

`README.zh-CN.md` 第 4 节末尾追加：

````markdown
### 正式测试脚本

`run_formal.sh` 依次运行：优化构建的有效签名（10 轮）、两组负例（各 5 轮，延迟上限 10 秒），
以及可移植构建的有效签名（10 轮）。所有运行共用 `corpus/`（或 `PQ_CORPUS_DIR`）下用 `--prepare-only`
预生成的样本，开始前先按 `SHA256SUMS` 核对，并把清单复制为 `corpus.SHA256SUMS`；快速模式改用
`OUTPUT_DIR/corpus` 下的临时小样本。最后用
`summarize.py` 生成 `summary.csv`。`host.txt` 记录 CPU 型号、`avx2`/`sha_ni` 等特性和调频策略。
按 Apple M 系列开发机估算，全程约 7 小时（不含首次生成样本），服务器上会有出入。

```bash
bash build.sh optimized && bash build.sh portable
PQ_CPU=2 nohup bash run_formal.sh results/formal-$(hostname)-$(date +%Y%m%d) > formal.log 2>&1 &
```

`PQ_CPU` 只在 Linux 上生效（`taskset`）；`PQ_FORMAL_QUICK=1` 改用几秒钟的参数，只用于检查流程。
````

`README.md` 追加对应英文段落：

````markdown
### Formal run script

`run_formal.sh` runs the optimized build on valid inputs (10 rounds) and on two
negative groups (5 rounds each, 10 s latency cap), then the portable build on valid
inputs (10 rounds). All runs share the corpus pre-generated with `--prepare-only`
under `corpus/` (or `PQ_CORPUS_DIR`), checked against `SHA256SUMS` first and copied
as `corpus.SHA256SUMS`; quick mode uses a throwaway corpus under `OUTPUT_DIR/corpus`.
`summarize.py` writes `summary.csv`. `host.txt` records the CPU model, features
such as `avx2`/`sha_ni`, and the frequency governor. Extrapolating from an Apple
M-series development machine, the whole run takes about 7 hours excluding first
corpus generation; servers will differ.

```bash
bash build.sh optimized && bash build.sh portable
PQ_CPU=2 nohup bash run_formal.sh results/formal-$(hostname)-$(date +%Y%m%d) > formal.log 2>&1 &
```

`PQ_CPU` applies on Linux only (`taskset`). `PQ_FORMAL_QUICK=1` substitutes
seconds-long settings to check the pipeline, not to measure.
````

- [ ] **Step 5: 提交**

```bash
chmod +x run_formal.sh
git add run_formal.sh README.md README.zh-CN.md
git commit -m "bench: add formal pq-verify run script"
```

---

### Task 7: 在目标 x86 Linux 服务器上正式测试（由人执行）

Agent 不操作云主机，以下步骤由人在目标机器上执行。

- [ ] **Step 1: 选机器并确认 CPU 特性**

选与验证节点同代、同型号的 x86 服务器。

Run: `lscpu | grep -E 'Model name|Thread|Core|Socket'; grep -o -w -E 'avx2|avx512f|bmi2|sha_ni' /proc/cpuinfo | sort -u`
Expected: 至少有 `avx2 bmi2`。没有 `sha_ni` 也能测，但 BoringSSL 会走 `avx`/`ssse3`，需要在报告中注明。

- [ ] **Step 2: 准备环境**

```bash
sudo cpupower frequency-set -g performance   # 或记录无法修改的原因
lscpu -e                                     # 选一个 SMT 兄弟线程空闲的物理核，记为 PQ_CPU
```

停掉无关负载，记录机器温度和电源策略。

把开发机上 Task 0b 生成的样本复制过去，不在服务器上重新签名（密钥不可复现，重签会换掉输入）：

```bash
# 开发机上
tar czf pq-corpus-k64-n16-m32.tgz corpus
# 服务器上，在仓库根目录解压
tar xzf pq-corpus-k64-n16-m32.tgz
(cd corpus && sha256sum -c SHA256SUMS)
```

- [ ] **Step 3: 安装依赖、构建并跑完整检查**

依赖：Rust 1.93、Git、CMake ≥ 3.24、GCC/G++ 或 Clang（C11 + C++17）、Python 3、`sha256sum`。

```bash
bash build.sh optimized && bash build.sh portable
export PQ_OQS_BUILD="$PWD/target/oqs-optimized"
cargo test --release --offline
python3 -m unittest test_summarize
python3 smoke_test.py ./target/pq-verify-optimized
```

Expected: 全部通过，冒烟测试显示 `(native dispatch)`。链接报 `undefined reference to operator delete` 之类错误时，检查是否装了 `libstdc++`。

- [ ] **Step 4: 运行**

```bash
PQ_CPU=<所选核> nohup bash run_formal.sh results/formal-$(hostname)-$(date +%Y%m%d) > formal.log 2>&1 &
```

- [ ] **Step 5: 验收结果**

- 4 个子目录都有 `COMPLETE`，`summary.csv` 已生成。
- `backend`：ML-DSA 为 `mldsa-native/x86_64`，Falcon 为 `PQClean/avx2`；`@boringssl` 行 `hash_backend` 在有 SHA-NI 的机器上为 `boringssl-sha256/hw`。
- 有效签名各行的 `verify_per_second_cv` 低于 0.02；超出时检查后台负载和调频，再重跑。
- 对比 `SLH_DSA_PURE_SHA2_128S@boringssl` 与 `SLH_DSA_PURE_SHA2_128S`、ML-DSA-44、Falcon-512 的 `throughput_vs_baseline`。

- [ ] **Step 6: 归档**

```bash
tar czf formal-$(hostname)-$(date +%Y%m%d).tgz -C results formal-$(hostname)-$(date +%Y%m%d) formal.log
```

结果目录已被 Git 忽略，不提交；把 `summary.csv` 和 `host.txt` 附到报告中。
