# PQ verification API benchmark (layer A)

English | [简体中文](README.zh-CN.md)

Independent Rust CLI over **liboqs 0.16.0**, pinned to
`5a1a854b0dc9f2141bdc771c555ee60c37950183`. It measures the complete native
verification API, including its internal decoding and hashing. SLH-DSA-SHA2-128s is
also measured with BoringSSL (pinned to `af41e135bc1714981fb8a791e9dda4fc6ff140c3`)
as a hardware-SHA-256 reference implementation. It was written for
NewL1 account-verification research but depends on no NewL1 code; NewL1 transaction
formats, execution and precompiles are out of scope.

The Cargo workspace has no registry dependencies. liboqs is an experimental
benchmark dependency only: one static C library, built separately by CMake;
OpenSSL is disabled. The C bridge reads metadata using the pinned C headers, so
Rust does not duplicate liboqs's struct layout. This is not a recommendation to
ship liboqs as the account verifier.

## Build and smoke test

Requires Rust 1.93+, Git, CMake 3.24+, C11 and C++17 compilers, `ar`, Make (or another CMake
generator), and `sha256sum` or `shasum`. Linux and macOS native builds are supported.
The first build downloads the pinned liboqs and BoringSSL sources. No system-wide installation
is needed. From the repository root:

```bash
bash build.sh optimized
./target/pq-verify-optimized --list
./target/pq-verify-optimized \
  --algorithms tier1 --cases all \
  --keys 2 --messages-per-key 2 --message-bytes 32 \
  --rounds 2 --warmup-ms 10 --duration-ms 100 --latency-samples 100 \
  --raw-latency --out results/smoke
```

These short settings check functionality, **not stable performance**. Output
directories must not exist; this prevents accidentally overwriting a measurement.
No arguments prints help. `--help` lists all options. `--list` prints all 18 entries
(17 liboqs parameter sets plus `SLH_DSA_PURE_SHA2_128S@boringssl`). Where CPU feature probes are
blocked, the optimized build refuses to run (see below); add `--allow-fallback`
for a functional check only.

For already downloaded, clean checkouts at the pinned commits:

```bash
PQ_OQS_SOURCE=/absolute/path/to/liboqs PQ_BSSL_SOURCE=/absolute/path/to/boringssl \
  bash build.sh optimized
```

`PQ_BUILD_JOBS` controls native build concurrency (default 4). `CC`/`CXX`/`AR` select
the native tools. Keep build tools and flags consistent across comparisons.

## Parameter sets and inputs

| Selection | Included parameter sets | NIST categories |
| --- | --- | --- |
| `tier1` (default) | ML-DSA-44; Falcon-512; SLH-DSA SHA2/SHAKE × 128s/128f; `SLH_DSA_PURE_SHA2_128S@boringssl` (7 entries) | 2; 1; 1 |
| `all` | ML-DSA-44/65/87; Falcon-512/1024; SLH-DSA SHA2/SHAKE × 128/192/256 × s/f; plus the BoringSSL entry (18 entries) | ML-DSA: 2/3/5; Falcon: 1/5; SLH-DSA: 1/3/5 |
| Comma-separated names | Exact names printed by `--list` | Per parameter set |

`tier1` means the lowest available parameters per family, **not equal security**.
For a three-family comparison at one category, select Category 5 parameters.
Falcon uses the original variable-length encoding, not `Falcon-padded` or a
future FN-DSA format. Actual signature lengths are recorded.

ML-DSA and SLH-DSA use their complete **pure** interfaces with empty context.
Passing a 32-byte message does not select HashML-DSA/HashSLH-DSA or bypass internal
hashing. Treating these bytes as an application digest is a protocol decision;
this benchmark does not establish the security strength of that digest.

Workload controls:

| Flags | Distribution |
| --- | --- |
| `--keys 1 --messages-per-key 1` | Repeated fixed input / hot-cache reference |
| `--keys 1 --messages-per-key 1024` | Same account, many messages |
| `--keys 64 --messages-per-key 16` | Many accounts / primary workload |
| Larger counts | Larger working set; compare bytes against the target CPU's LLC |

The default is 8 keys × 8 messages, 32 bytes, valid inputs, 5 rounds, 1 second
warmup, 3 seconds throughput, and 10,000 latency observations per round. Use
explicit formal settings below for a report. Message length must be positive;
32, 64, 256, 1024, and 4096 bytes are useful separate runs.

`--cases all` includes valid, wrong-message, wrong-key, corrupt-head, corrupt-mid,
corrupt-tail, truncated, and extended. Negative cases retain a correctly sized
public key; the liboqs API does not take a public-key length. Wrong-message flips
one message bit while retaining a valid signature, exercising cryptographic
rejection rather than only malformed-input rejection. Wrong-key verifies against
the next account's public key (the extra key only when there is one account), so
its public-key working set matches `valid`. The corrupt cases flip one bit in the
first, middle or last signature byte. Truncation removes one byte; extension
appends `0xff`, not zero, because Falcon accepts zero bytes that pad a signature
to its fixed padded size, so appending zero to one a byte short is valid. Different failures can have very different rejection costs; they
are never pooled. Corruption position matters most: Falcon-512 rejects a bad
header byte in under 100 ns, a bad last byte in about 3 µs, and a bad middle
byte only after full verification (about 25 µs).

## Formal measurements

Use an idle machine representative of validators. On Linux, select an available
physical CPU and pin the benchmark with `taskset -c CPU`. Record frequency policy,
SMT, power limits, background load and temperature in an accompanying environment
note. The tool records CPU information and Linux CPU/memory affinity, but does
not change host settings. macOS measurements are not CPU-pinned by this tool.

```bash
./target/pq-verify-optimized \
  --algorithms all --cases valid \
  --keys 64 --messages-per-key 16 --message-bytes 32 \
  --rounds 10 --warmup-ms 3000 --duration-ms 10000 \
  --latency-samples 100000 --latency-max-ms 20000 --seed 42 \
  --corpus-dir corpus --out results/all-valid-32
```

`--latency-max-ms` bounds each latency measurement: it stops at
`--latency-samples` observations or the time limit, whichever comes first, and
`latency_samples` records the actual count. Uncapped, SLH-DSA's 0.4–2.2 ms per
verification makes the command above take about 29 minutes per round (about
5 hours for 10 rounds) on an Apple M-series development machine; a 20 s cap
brings that to about 8 minutes per round while SLH-DSA still collects roughly
9,000–46,000 observations, enough for P99. Lattice schemes still reach 100,000.

SLH-DSA signing is slow: `s` sets take 0.5–1 s per signature, so generating all
17 parameter sets at 64×16 one after another takes over an hour. It is entirely
outside timing, but generate it once up front with `--prepare-only`, which only
generates and validates corpora, prints a `sha256sum`-format manifest to stdout,
does no timing and does not create `--out`. Parameter sets are independent, so
generate them in parallel. Exclude the `@boringssl` entry: it reads and writes the
corpus file of the liboqs parameter set of the same name, so two processes would
write one file:

```bash
mkdir -p corpus && ./target/pq-verify-optimized --list | grep -v @ | xargs -P 8 -n 1 \
  ./target/pq-verify-optimized --prepare-only \
  --keys 64 --messages-per-key 16 --message-bytes 32 --corpus-dir corpus \
  --algorithms > corpus/SHA256SUMS
```

Reuse that corpus for subsequent runs, alternative builds and hosts. After copying
it to another host, check `(cd corpus && shasum -a 256 -c SHA256SUMS)`; loading
also re-validates every positive and negative case.
Run negative cases separately, for example `--cases wrong-message,wrong-key`,
then malformed signatures with
`--cases corrupt-head,corrupt-mid,corrupt-tail,truncated,extended`.

Build and compare the portable configuration using the **same corpus**:

```bash
bash build.sh portable
./target/pq-verify-portable \
  --algorithms tier1 --cases valid --keys 64 --messages-per-key 16 \
  --rounds 10 --warmup-ms 3000 --duration-ms 10000 --latency-samples 100000 \
  --latency-max-ms 20000 --corpus-dir corpus --out results/portable-valid-32
```

`optimized`: Release, generic base CPU plus liboqs runtime dispatch to supported
optimized implementations (`OQS_DIST_BUILD=ON`). `portable`: Release, generic
CPU, no distribution dispatch (`OQS_DIST_BUILD=OFF`), explicitly disabled liboqs
CPU-extension switches, and a check that no architecture-specific signature
backend was enabled. Generic compiler auto-vectorization is still allowed.
The selected signature backend (`backend`) and hash backend (`hash_backend`) are
derived from the pinned dispatch rules and saved in each row; compiled
configuration and CMake cache are embedded in the executable's metadata. Results
characterize these implementations and their optimization maturity, not universal
algorithm limits.

**Cross-family comparisons disadvantage SLH-DSA.** In this pin SLH-DSA uses
slhdsa-c portable code in both builds, and slhdsa-c bundles its own scalar SHA-2
and Keccak instead of liboqs's dispatched hashes, so it never uses SHA-NI or
ARMv8 SHA2 instructions. Its optimized and portable results are therefore
essentially identical, while ML-DSA and Falcon use SIMD backends in the optimized
build. Production SLH-DSA implementations (hardware SHA-2, AVX2 multi-way hashing)
can be several times faster. A cross-family ratio from one build combines
algorithm and implementation maturity; do not attribute it to the algorithm alone.

**Getting a fair comparison.** For the algorithms themselves, compare portable
builds: all three families are plain C, and BoringSSL is built with
`OPENSSL_NO_ASM`. For deployment cost, use `SLH_DSA_PURE_SHA2_128S@boringssl` in
the optimized build: it uses hardware SHA-256, shares the corpus file of liboqs's
`SLH_DSA_PURE_SHA2_128S`, and revalidates every positive and negative sample with
BoringSSL before timing, failing if the libraries disagree. On an Apple M-series
development machine it verifies in about 1/6 of liboqs's time. BoringSSL's
SHAKE-256f also uses portable Keccak and measured about 15% slower than liboqs, so
it is not included.

**The optimized build refuses silent fallback.** Restricted environments can block
CPU feature probes (e.g. macOS `sysctl`), making runtime dispatch select generic C.
If any ML-DSA or Falcon parameter set resolves to `mldsa-native/C` or
`PQClean/clean`, or BoringSSL's SHA-256 resolves to `boringssl-sha256/nohw`, the
run fails before creating outputs. To record such a run
deliberately (e.g. a CPU without the extensions), pass `--allow-fallback`; rows
then show the C backend and metadata records `dist_build=true`. Formal runs should
have normal CPU-feature visibility.

## Timing and reproducibility

- Generate keys/messages/signatures using liboqs's default OS-backed randomness.
  Save only public keys, messages and signatures, including a separate wrong key.
  Secret keys are cleansed on drop and never serialized.
- Load or generate **all** corpora before measurements; validate all positive and
  negative samples before timing. Malformed/stale corpora cause an error rather
  than regeneration. Every timed result must match its expected validity.
- Save corpus SHA-256 hashes. `--seed` controls only sample and job shuffling, not
  cryptographic randomness. Copy corpus files to reproduce the exact inputs.
- Shuffle algorithm/case job order each round; shuffle sample traversal before
  warmup. Each traversal visits the whole corpus before repeating. No verification
  result cache or predecoded public-key cache is used.
- Latency: preallocate the observations array, clock individual verification calls,
  then check validity and store results after stopping each timer. Mean and nearest-
  rank P50/P95/P99 are computed from individual calls. Scheduling interruptions
  remain in the distribution. With `--latency-max-ms`, sampling stops once the
  limit elapses (keeping at least one observation); the deadline check is outside
  each per-call timer. Record a separate empty timer probe; do not subtract it
  from measurements (particularly relevant for cheap malformed-input rejection).
- Timer resolution: Apple Silicon's timer ticks at about 41.7 ns (probe p50 0,
  p99 about 42 ns). Sub-microsecond cases such as `truncated`, `extended` and
  Falcon `corrupt-head` quantize to multiples of it; use `verify_per_second` for
  them. macOS also cannot restrict the process to performance cores; take formal
  numbers on Linux.
- Throughput: independently time a loop; check the deadline every 64 calls. Count
  all calls and the full elapsed duration, including overshoot. This includes the
  small traversal/result-check overhead. `verify_per_second = calls / elapsed`.
  For negative cases, this is rejection throughput, not accepted signatures/s.
- Alternate latency/throughput order between rounds. Corpus I/O, RNG, signing,
  sorting, progress logging and CSV writes never occur in a timed region.

Outputs:

| File | Contents |
| --- | --- |
| `rounds.csv` | Every parameter/case/round, signature and hash backends, category, corpus hash, sizes, actual latency sample count, latency statistics and independently measured throughput |
| `latency.csv` | Optional `--raw-latency`: individual observations, indexed in measurement order, not original corpus order |
| `metadata.txt` | Exact options, liboqs revision/config/compiler, Rust version/flags, executable hash, CPU/OS/affinity, corpus hashes and timer probe |
| `COMPLETE` | Written only after all requested measurements and output flushes succeed |

`corpus/*.bin` uses a versioned, bounded, length-prefixed little-endian format.
An interrupted run may leave partial outputs; absence of `COMPLETE` means it is
not a completed result. Remove an interrupted corpus file explicitly before
regenerating it. Generated artifacts and native builds are gitignored.

Keep per-round observations when deriving confidence intervals; do not mistake
100,000 repeated calls within a round for 100,000 independent experiments. This
tool emits raw measurements rather than choosing a cross-round statistical model.

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

## Checks

After an optimized build:

```bash
export PQ_OQS_BUILD="$PWD/target/oqs-optimized"
cargo fmt --all -- --check
cargo clippy --release --all-targets --offline -- -D warnings
cargo test --release --offline
python3 -m unittest test_summarize
python3 smoke_test.py ./target/pq-verify-optimized
```

Tests exercise all 18 entries with real valid/invalid signatures, wrong-key
rotation, serialized corpus replay and corruption rejection, two-way BoringSSL/liboqs
corpus interoperability, measurement failure detection, the latency budget,
fallback-backend classification, traversal, and quantile calculations. The smoke
test covers 18 entries × 8 cases and checks
the CLI, output arithmetic, that the `--prepare-only` manifest matches the files,
is not regenerated on a second run and is what measurement runs consume, corpus
reuse, the latency budget and failure handling.
It runs with `--allow-fallback` so it also passes in restricted environments; when
it detects a fallback it additionally checks that a run without the flag is refused.

Scope is single-thread layer A for the three PQ families. Mixed-invalid workloads,
multi-core scaling, secp256k1 baselines, account identity binding, EVM/precompile
costs, block throughput and gas pricing are not measured here. Only SLH-DSA-SHA2-128s
has a second (BoringSSL) implementation; the other SLH-DSA sets use liboqs's scalar
code (see above). `verify/s` is not chain TPS.

References: [liboqs 0.16.0](https://github.com/open-quantum-safe/liboqs/tree/0.16.0),
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final),
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
