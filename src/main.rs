//! Measures complete liboqs verification APIs independently of NewL1 execution.
//! Key generation, signing, corpus I/O and reporting are outside timed regions.

mod corpus;
mod measure;
mod oqs;

use std::{
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use corpus::{Case, Corpus};
use measure::OrderRng;
use oqs::Verifier;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct Options {
    algorithms: Vec<String>,
    cases: Vec<Case>,
    keys: usize,
    messages_per_key: usize,
    message_bytes: usize,
    rounds: usize,
    warmup: Duration,
    duration: Duration,
    latency_samples: usize,
    latency_budget: Option<Duration>,
    seed: u64,
    corpus_dir: PathBuf,
    out: PathBuf,
    raw_latency: bool,
    allow_fallback: bool,
    prepare_only: bool,
}

struct Dataset {
    verifier: Verifier,
    corpus: Corpus,
    sha256: String,
}

const HELP: &str = "pq-verify-bench: single-thread complete verification API benchmark

  --algorithms tier1|all|NAME,NAME  default: tier1 (6 parameter sets)
  --cases valid|all|CASE,CASE       default: valid
      cases: valid,wrong-message,wrong-key,corrupt-head,corrupt-mid,
             corrupt-tail,truncated,extended
  --keys N                         default: 8
  --messages-per-key N             default: 8
  --message-bytes N                default: 32; must be positive
  --rounds N                       default: 5
  --warmup-ms N                    default: 1000; may be zero for smoke tests
  --duration-ms N                  default: 3000, per throughput measurement
  --latency-samples N              default: 10000, per round
  --latency-max-ms N               default: unlimited; stop latency sampling early
                                   once N ms elapse (rounds.csv keeps the count)
  --seed N                         default: 42; traversal only, NOT key generation
  --corpus-dir PATH                default: corpus
  --out PATH                       default: results/run-<timestamp>; must not exist
  --raw-latency                    also write individual latency samples
  --allow-fallback                 run even if a dispatching build selected generic
                                   C for ML-DSA/Falcon (blocked CPU detection)
  --prepare-only                   generate/validate corpora, print sha256sum lines
                                   to stdout and exit; no timing, --out unused
  --list                          list all 17 supported parameter sets
  --help                          show this message

Run a Release build. Reuse saved corpora across machines/builds. No result cache.
";

fn all_algorithms() -> Vec<String> {
    let mut names = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512", "Falcon-1024"]
        .map(str::to_owned)
        .to_vec();
    for hash in ["SHA2", "SHAKE"] {
        for bits in [128, 192, 256] {
            for variant in ["S", "F"] {
                names.push(format!("SLH_DSA_PURE_{hash}_{bits}{variant}"));
            }
        }
    }
    names
}

fn tier1() -> Vec<String> {
    all_algorithms()
        .into_iter()
        .filter(|name| name == "ML-DSA-44" || name == "Falcon-512" || name.contains("128"))
        .collect()
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut opts = Self {
            algorithms: tier1(),
            cases: vec![Case::Valid],
            keys: 8,
            messages_per_key: 8,
            message_bytes: 32,
            rounds: 5,
            warmup: Duration::from_secs(1),
            duration: Duration::from_secs(3),
            latency_samples: 10_000,
            latency_budget: None,
            seed: 42,
            corpus_dir: "corpus".into(),
            out: format!("results/run-{timestamp}").into(),
            raw_latency: false,
            allow_fallback: false,
            prepare_only: false,
        };
        let mut args = args;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--raw-latency" => {
                    opts.raw_latency = true;
                    continue;
                }
                "--allow-fallback" => {
                    opts.allow_fallback = true;
                    continue;
                }
                "--prepare-only" => {
                    opts.prepare_only = true;
                    continue;
                }
                _ => {}
            }
            let value = args.next().ok_or_else(|| format!("missing value for {arg}"))?;
            match arg.as_str() {
                "--algorithms" => {
                    opts.algorithms = match value.as_str() {
                        "tier1" => tier1(),
                        "all" => all_algorithms(),
                        _ => value.split(',').map(str::to_owned).collect(),
                    };
                    let supported = all_algorithms();
                    for name in &opts.algorithms {
                        if !supported.contains(name) {
                            return Err(format!("unsupported algorithm: {name}; use --list").into());
                        }
                    }
                }
                "--cases" => {
                    opts.cases = if value == "all" {
                        Case::ALL.to_vec()
                    } else {
                        value
                            .split(',')
                            .map(|name| {
                                Case::ALL
                                    .into_iter()
                                    .find(|c| c.name() == name)
                                    .ok_or_else(|| format!("unknown case: {name}"))
                            })
                            .collect::<std::result::Result<_, _>>()?
                    };
                }
                "--keys" => opts.keys = value.parse()?,
                "--messages-per-key" => opts.messages_per_key = value.parse()?,
                "--message-bytes" => opts.message_bytes = value.parse()?,
                "--rounds" => opts.rounds = value.parse()?,
                "--warmup-ms" => opts.warmup = Duration::from_millis(value.parse()?),
                "--duration-ms" => opts.duration = Duration::from_millis(value.parse()?),
                "--latency-samples" => opts.latency_samples = value.parse()?,
                "--latency-max-ms" => {
                    let budget = Duration::from_millis(value.parse()?);
                    if budget.is_zero() || budget > Duration::from_secs(3600) {
                        return Err("latency-max-ms must be 1..=3600000".into());
                    }
                    opts.latency_budget = Some(budget);
                }
                "--seed" => opts.seed = value.parse()?,
                "--corpus-dir" => opts.corpus_dir = value.into(),
                "--out" => opts.out = value.into(),
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }
        for (name, n, maximum) in [
            ("keys", opts.keys, 65_536),
            ("messages-per-key", opts.messages_per_key, 65_536),
            ("message-bytes", opts.message_bytes, 1_048_576),
            ("rounds", opts.rounds, 1000),
            ("latency-samples", opts.latency_samples, 10_000_000),
        ] {
            if n == 0 || n > maximum {
                return Err(format!("{name} must be in 1..={maximum}").into());
            }
        }
        if opts.duration.is_zero()
            || opts.duration > Duration::from_secs(3600)
            || opts.warmup > Duration::from_secs(3600)
        {
            return Err("duration must be 1..=3600000 ms; warmup 0..=3600000 ms".into());
        }
        if opts.algorithms.iter().enumerate().any(|(i, a)| opts.algorithms[..i].contains(a))
            || opts.cases.iter().enumerate().any(|(i, c)| opts.cases[..i].contains(c))
        {
            return Err("duplicate algorithms or cases".into());
        }
        Ok(opts)
    }
}

fn sha256(path: &Path) -> Result<String> {
    let path = path.canonicalize()?;
    // Run outside timing; avoid adding a second cryptographic library just for artifacts.
    for (program, arguments) in [("sha256sum", vec![]), ("shasum", vec!["-a", "256"])] {
        if let Ok(output) = Command::new(program).args(arguments).arg(&path).output()
            && output.status.success()
        {
            let text = String::from_utf8(output.stdout)?;
            let hash = text.split_whitespace().next().ok_or("empty checksum output")?;
            if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(hash.to_owned());
            }
        }
    }
    Err("sha256sum or shasum is required to identify corpus/build artifacts".into())
}

fn record_command(output: &mut impl Write, program: &str, args: &[&str]) -> Result<()> {
    writeln!(output, "\n$ {program} {}", args.join(" "))?;
    match Command::new(program).args(args).output() {
        Ok(result) => {
            output.write_all(&result.stdout)?;
            output.write_all(&result.stderr)?;
        }
        Err(error) => writeln!(output, "unavailable: {error}")?,
    }
    Ok(())
}

fn load_corpus(opts: &Options, verifier: &Verifier) -> Result<(PathBuf, Corpus)> {
    let file = opts.corpus_dir.join(format!(
        "{}-k{}-n{}-m{}.bin",
        verifier.name, opts.keys, opts.messages_per_key, opts.message_bytes
    ));
    let verb = if file.exists() { "Validating" } else { "Generating" };
    eprintln!(
        "{verb} {}: {} keys × {} messages (outside timing)",
        verifier.name, opts.keys, opts.messages_per_key
    );
    let start = Instant::now();
    let corpus = Corpus::load_or_generate(
        &file,
        verifier,
        opts.keys,
        opts.messages_per_key,
        opts.message_bytes,
    )?;
    eprintln!("{}: corpus ready in {:.1?}", verifier.name, start.elapsed());
    Ok((file, corpus))
}

fn run(opts: &Options) -> Result<()> {
    if cfg!(debug_assertions) {
        return Err("use a --release build for benchmarking".into());
    }
    let version = oqs::init();
    if version != "0.16.0" {
        return Err(format!("expected liboqs 0.16.0, got {version}").into());
    }
    let verifiers =
        opts.algorithms.iter().map(|name| Verifier::new(name)).collect::<Result<Vec<_>>>()?;
    let estimated_bytes: u128 = verifiers
        .iter()
        .map(|v| {
            (opts.keys as u128 + 1) * v.public_key_len as u128
                + opts.keys as u128
                    * opts.messages_per_key as u128
                    * (opts.message_bytes + v.signature_max + 128) as u128
        })
        .sum();
    if estimated_bytes > 2 * 1024 * 1024 * 1024 {
        return Err("corpora exceed the 2 GiB input limit; split the run".into());
    }
    fs::create_dir_all(&opts.corpus_dir)?;
    // Signing dominates (SLH-DSA `s` sets take 0.5-1 s per signature, over an hour
    // for 17 sets at 64x16) and keys are unseeded: corpora are made once, then copied.
    if opts.prepare_only {
        for verifier in &verifiers {
            let (file, _) = load_corpus(opts, verifier)?;
            let name = file.file_name().ok_or("corpus path has no file name")?;
            println!("{}  {}", sha256(&file)?, name.display());
        }
        return Ok(());
    }
    let dist_build = oqs::dist_build();
    // Checked before creating outputs: a fallback run otherwise completes normally and
    // reports C-code timings under an "optimized" build name.
    if dist_build
        && !opts.allow_fallback
        && let Some(v) = verifiers.iter().find(|v| oqs::is_fallback_backend(&v.backend))
    {
        return Err(format!(
            "{} dispatched to {} in a runtime-dispatch build: CPU feature detection \
             is blocked (e.g. sandboxed sysctl) or the CPU lacks the extensions. \
             Run where detection works, or pass --allow-fallback to record it anyway",
            v.name, v.backend
        )
        .into());
    }
    if let Some(parent) = opts.out.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&opts.out)?;
    let mut metadata = BufWriter::new(File::create(opts.out.join("metadata.txt"))?);
    writeln!(
        metadata,
        "options={opts:#?}\nliboqs={version}\ndist_build={dist_build}\nrustc={}\nrustflags={}\narch={}\nos={}\nthreads=1\ncontext=empty\nmode=pure-message-api\n",
        env!("PQ_RUSTC"),
        env!("PQ_RUSTFLAGS"),
        env::consts::ARCH,
        env::consts::OS
    )?;
    writeln!(metadata, "executable_sha256={}", sha256(&env::current_exe()?)?)?;
    metadata.write_all(include_bytes!(env!("PQ_BUILD_PROVENANCE")))?;
    metadata.write_all(include_bytes!(env!("PQ_BUILD_CONFIG")))?;
    record_command(&mut metadata, "uname", &["-a"])?;
    if cfg!(target_os = "linux") {
        record_command(&mut metadata, "lscpu", &[])?;
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines().filter(|l| {
                l.starts_with("Cpus_allowed_list:") || l.starts_with("Mems_allowed_list:")
            }) {
                writeln!(metadata, "{line}")?;
            }
        }
    } else if cfg!(target_os = "macos") {
        record_command(
            &mut metadata,
            "sysctl",
            &["machdep.cpu.brand_string", "hw.physicalcpu", "hw.logicalcpu", "hw.memsize"],
        )?;
    }
    metadata.flush()?;

    let mut datasets = Vec::new();
    for verifier in verifiers {
        let (file, corpus) = load_corpus(opts, &verifier)?;
        let sha256 = sha256(&file)?;
        writeln!(
            metadata,
            "\nalgorithm={}\nalgorithm_version={}\nverification_backend={}\nhash_backend={}\ncategory={}\npublic_key_bytes={}\nsignature_max_bytes={}\ncorpus={}\ncorpus_sha256={}",
            verifier.name,
            verifier.version,
            verifier.backend,
            verifier.hash_backend,
            verifier.category,
            verifier.public_key_len,
            verifier.signature_max,
            file.canonicalize()?.display(),
            sha256
        )?;
        metadata.flush()?;
        datasets.push(Dataset { verifier, corpus, sha256 });
    }
    let timer = measure::latency(1, 10_000, None, |_| std::hint::black_box(true), true)?;
    writeln!(
        metadata,
        "\ntimer_probe_p50_ns={}\ntimer_probe_p99_ns={}\nTimer probe is diagnostic only; it is not subtracted.",
        timer.p50_ns, timer.p99_ns
    )?;
    metadata.flush()?;
    let mut csv = BufWriter::new(File::create(opts.out.join("rounds.csv"))?);
    writeln!(
        csv,
        "algorithm,backend,hash_backend,category,case,round,keys,messages_per_key,message_bytes,corpus_sha256,pk_bytes,input_sig_min_bytes,input_sig_mean_bytes,input_sig_max_bytes,latency_samples,mean_ns,p50_ns,p95_ns,p99_ns,throughput_calls,throughput_elapsed_ns,verify_per_second"
    )?;
    let mut raw = if opts.raw_latency {
        let mut file = BufWriter::new(File::create(opts.out.join("latency.csv"))?);
        writeln!(file, "algorithm,case,round,observation_index,elapsed_ns")?;
        Some(file)
    } else {
        None
    };
    let mut rng = OrderRng(opts.seed);
    for round in 1..=opts.rounds {
        let mut jobs: Vec<_> = (0..datasets.len())
            .flat_map(|i| opts.cases.iter().map(move |&case| (i, case)))
            .collect();
        rng.shuffle(&mut jobs);
        for (index, case) in jobs {
            let Dataset { verifier, corpus, sha256 } = &datasets[index];
            let mut inputs = corpus.inputs(case);
            rng.shuffle(&mut inputs);
            let expected = case == Case::Valid;
            let verify = |i: usize| {
                let input = &inputs[i];
                verifier.verify(input.pk, &input.message, &input.signature)
            };
            eprintln!("Round {round}/{}: {} / {}", opts.rounds, verifier.name, case.name());
            if !opts.warmup.is_zero() {
                measure::throughput(inputs.len(), opts.warmup, |i| verify(i) == expected)?;
            }
            // Alternate order to avoid always measuring throughput after latency heats the CPU.
            let latency = || {
                measure::latency(
                    inputs.len(),
                    opts.latency_samples,
                    opts.latency_budget,
                    verify,
                    expected,
                )
            };
            let throughput =
                || measure::throughput(inputs.len(), opts.duration, |i| verify(i) == expected);
            let (latency, throughput) = if round % 2 == 1 {
                let l = latency()?;
                (l, throughput()?)
            } else {
                let t = throughput()?;
                (latency()?, t)
            };
            let min = inputs.iter().map(|s| s.signature.len()).min().unwrap();
            let max = inputs.iter().map(|s| s.signature.len()).max().unwrap();
            let mean =
                inputs.iter().map(|s| s.signature.len() as f64).sum::<f64>() / inputs.len() as f64;
            writeln!(
                csv,
                "{},{},{},{},{},{round},{},{},{},{sha256},{},{min},{mean:.3},{max},{},{:.3},{},{},{},{},{},{:.3}",
                verifier.name,
                verifier.backend,
                verifier.hash_backend,
                verifier.category,
                case.name(),
                opts.keys,
                opts.messages_per_key,
                opts.message_bytes,
                verifier.public_key_len,
                latency.samples.len(),
                latency.mean_ns,
                latency.p50_ns,
                latency.p95_ns,
                latency.p99_ns,
                throughput.calls,
                throughput.elapsed.as_nanos(),
                throughput.calls as f64 / throughput.elapsed.as_secs_f64()
            )?;
            csv.flush()?;
            if let Some(raw) = &mut raw {
                for (i, ns) in latency.samples.iter().enumerate() {
                    writeln!(raw, "{},{},{round},{i},{ns}", verifier.name, case.name())?;
                }
                raw.flush()?;
            }
        }
    }
    fs::write(
        opts.out.join("COMPLETE"),
        "All requested measurements completed and verification outcomes matched.\n",
    )?;
    eprintln!("Results: {}", opts.out.canonicalize()?.display());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args == ["--help"] || args.is_empty() {
        print!("{HELP}");
        return Ok(());
    }
    if args == ["--list"] {
        for name in all_algorithms() {
            println!("{name}");
        }
        return Ok(());
    }
    run(&Options::parse(args.into_iter())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_matrix_and_cli_reject_invalid_workloads() {
        assert_eq!(all_algorithms().len(), 17);
        assert_eq!(tier1().len(), 6);
        for args in [
            vec!["--keys", "0"],
            vec!["--message-bytes", "0"],
            vec!["--duration-ms", "0"],
            vec!["--latency-samples", "0"],
            vec!["--latency-max-ms", "0"],
            vec!["--algorithms", "SPHINCS+"],
            vec!["--cases", "valid,valid"],
            vec!["--cases", "corrupt-signature"],
            vec!["--rounds"],
        ] {
            assert!(Options::parse(args.into_iter().map(str::to_owned)).is_err());
        }
        let opts = Options::parse(
            ["--allow-fallback", "--latency-max-ms", "5", "--raw-latency", "--prepare-only"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert!(opts.allow_fallback && opts.raw_latency && opts.prepare_only);
        assert_eq!(opts.latency_budget, Some(Duration::from_millis(5)));
    }
}
