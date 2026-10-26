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
