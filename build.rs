//! Links a separately built, pinned liboqs without downloading during Cargo builds.

use std::{env, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    let status = command.status().expect("could not start native build command");
    assert!(status.success(), "native build failed: {command:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=native.c");
    for name in ["PQ_OQS_BUILD", "CC", "AR"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let root = PathBuf::from(env::var_os("PQ_OQS_BUILD").expect("run ./build.sh first"));
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    for file in ["lib/liboqs.a", "include/oqs/oqsconfig.h", "provenance.txt"] {
        println!("cargo:rerun-if-changed={}", root.join(file).display());
    }
    assert_eq!(env::var("HOST"), env::var("TARGET"), "native builds only");
    run(Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args(["-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(root.join("include"))
        .args(["-c", "native.c", "-o"])
        .arg(out.join("native.o")));
    run(Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
        .arg("crs")
        .arg(out.join("libpq_bridge.a"))
        .arg(out.join("native.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", root.join("lib").display());
    println!("cargo:rustc-link-lib=static=pq_bridge");
    println!("cargo:rustc-link-lib=static=oqs");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-env=PQ_BUILD_PROVENANCE={}", root.join("provenance.txt").display());
    println!("cargo:rustc-env=PQ_BUILD_CONFIG={}", root.join("include/oqs/oqsconfig.h").display());
    let rustc = Command::new(env::var_os("RUSTC").unwrap()).arg("--version").output().unwrap();
    println!("cargo:rustc-env=PQ_RUSTC={}", String::from_utf8_lossy(&rustc.stdout).trim());
    println!(
        "cargo:rustc-env=PQ_RUSTFLAGS={}",
        env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default().replace('\x1f', " ")
    );
}
