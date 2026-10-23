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
        .args(["-std=c11", "-O3", "-fPIC", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(root.join("include"))
        .args(["-c", "native.c", "-o"])
        .arg(out.join("native.o")));
    let mut bridge = Command::new(env::var_os("CXX").unwrap_or_else(|| "c++".into()));
    // -isystem: BoringSSL's internal headers are not -Wextra clean.
    // -fPIC here and in native.c: Rust links PIE executables on Linux.
    bridge
        .args(["-std=c++17", "-O3", "-fPIC", "-Wall", "-Wextra", "-Werror", "-isystem"])
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
