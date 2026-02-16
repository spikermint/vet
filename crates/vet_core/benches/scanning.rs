//! Benchmarks for the scanning engine.
//!
//! Run with: cargo bench -p `vet_core`

#![expect(clippy::expect_used, reason = "benchmarks use expect for setup code")]

use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use vet_core::prelude::*;

/// Sample content with no secrets (common case).
const CLEAN_CODE: &str = r#"
fn main() {
    let config = Config::load("settings.toml").unwrap();
    let server = Server::new(config.host, config.port);
    server.run().expect("server failed");
}
"#;

/// Sample content with a secret embedded.
const CODE_WITH_SECRET: &str = r#"
fn main() {
    let api_key = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
    let client = Client::new(api_key);
}
"#;

fn bench_scanner_creation(c: &mut Criterion) {
    c.bench_function("scanner_builtin_creation", |b| {
        b.iter(|| {
            let registry = PatternRegistry::builtin().expect("builtin patterns");
            let scanner = Scanner::new(registry);
            black_box(scanner)
        });
    });
}

fn bench_scan_clean_file(c: &mut Criterion) {
    let registry = PatternRegistry::builtin().expect("builtin patterns");
    let scanner = Scanner::new(registry);
    let path = Path::new("example.rs");

    let mut group = c.benchmark_group("scan_clean");
    group.throughput(Throughput::Bytes(CLEAN_CODE.len() as u64));

    group.bench_function("small_file", |b| {
        b.iter(|| {
            let findings = scanner.scan_content(black_box(CLEAN_CODE), path);
            black_box(findings)
        });
    });

    // Simulate a larger file by repeating content
    let large_content = CLEAN_CODE.repeat(1000);
    group.throughput(Throughput::Bytes(large_content.len() as u64));

    group.bench_function("large_file", |b| {
        b.iter(|| {
            let findings = scanner.scan_content(black_box(&large_content), path);
            black_box(findings)
        });
    });

    group.finish();
}

fn bench_scan_with_secret(c: &mut Criterion) {
    let registry = PatternRegistry::builtin().expect("builtin patterns");
    let scanner = Scanner::new(registry);
    let path = Path::new("example.rs");

    let mut group = c.benchmark_group("scan_with_secret");
    group.throughput(Throughput::Bytes(CODE_WITH_SECRET.len() as u64));

    group.bench_function("single_secret", |b| {
        b.iter(|| {
            let findings = scanner.scan_content(black_box(CODE_WITH_SECRET), path);
            black_box(findings)
        });
    });

    group.finish();
}

fn bench_keyword_filtering(c: &mut Criterion) {
    let registry = PatternRegistry::builtin().expect("builtin patterns");
    let scanner = Scanner::new(registry);
    let path = Path::new("example.rs");

    // Content with keywords but no actual matches (tests keyword pre-filter)
    let content_with_keywords = r#"
        // This mentions ghp_ and AKIA but has no real tokens
        // The keyword filter should activate patterns but regex won't match
        let docs = "See ghp_ prefix for GitHub tokens";
        let note = "AWS keys start with AKIA";
    "#;

    c.bench_function("keyword_prefilter", |b| {
        b.iter(|| {
            let findings = scanner.scan_content(black_box(content_with_keywords), path);
            black_box(findings)
        });
    });
}

criterion_group!(
    benches,
    bench_scanner_creation,
    bench_scan_clean_file,
    bench_scan_with_secret,
    bench_keyword_filtering,
);

criterion_main!(benches);
