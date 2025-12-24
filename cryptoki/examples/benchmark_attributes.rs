// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Benchmark example comparing get_attributes_old vs get_attributes
//!
//! This example demonstrates the performance difference between the original
//! and optimized implementations for retrieving object attributes.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::env;
use std::time::Instant;

/// Statistics for a benchmark run
/// API calls are typically log-normally distributed, so we use that distribution
/// to compute geometric mean and percentiles.
struct BenchmarkStats {
    mean: f64,
    stddev: f64,
    p50: f64,
    p95: f64,
    p99: f64,
}

impl BenchmarkStats {
    fn from_timings(mut timings: Vec<f64>) -> Self {
        let iterations = timings.len();
        timings.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let p50 = timings[iterations / 2];
        let p95 = timings[(iterations * 95) / 100];
        let p99 = timings[(iterations * 99) / 100];

        // Geometric mean (appropriate for log-normal distribution)
        let mean = (timings.iter().map(|x| x.ln()).sum::<f64>() / iterations as f64).exp();

        // Standard deviation in log-space (geometric standard deviation)
        let log_mean = timings.iter().map(|x| x.ln()).sum::<f64>() / iterations as f64;
        let log_variance = timings
            .iter()
            .map(|x| (x.ln() - log_mean).powi(2))
            .sum::<f64>()
            / iterations as f64;
        let stddev = log_variance.sqrt().exp();

        BenchmarkStats {
            mean,
            stddev,
            p50,
            p95,
            p99,
        }
    }

    fn print(&self, label: &str) {
        println!("  {}:", label);
        println!("    distribution:   log-normal");
        println!("    mean (geom):    {:.2} µs", self.mean / 1000.0);
        println!("    std dev (geom): {:.2}x", self.stddev);
        println!("    p50 (median):   {:.2} µs", self.p50 / 1000.0);
        println!("    p95:            {:.2} µs", self.p95 / 1000.0);
        println!("    p99:            {:.2} µs", self.p99 / 1000.0);
    }
}

struct BenchmarkResult {
    label: String,
    stats_old: BenchmarkStats,
    stats_optimized: BenchmarkStats,
}

impl BenchmarkResult {
    fn speedup_mean(&self) -> f64 {
        self.stats_old.mean / self.stats_optimized.mean
    }
}

/// Run a benchmark comparing get_attributes_old vs get_attributes
fn benchmark_attributes(
    session: &Session,
    object: ObjectHandle,
    attributes: &[AttributeType],
    iterations: usize,
    label: &str,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    println!("\n=== {} ===", label);

    // Benchmark get_attributes_old (original implementation)
    println!(
        "Benchmarking get_attributes_old() - {} iterations...",
        iterations
    );
    let mut timings_old = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _attrs = session.get_attributes_old(object, attributes)?;
        timings_old.push(start.elapsed().as_nanos() as f64);
    }

    // Benchmark get_attributes (optimized implementation)
    println!(
        "Benchmarking get_attributes() - {} iterations...",
        iterations
    );
    let mut timings_optimized = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _attrs = session.get_attributes(object, attributes)?;
        timings_optimized.push(start.elapsed().as_nanos() as f64);
    }

    let stats_old = BenchmarkStats::from_timings(timings_old);
    let stats_optimized = BenchmarkStats::from_timings(timings_optimized);

    println!("\nResults:");
    stats_old.print("Original implementation");
    stats_optimized.print("Optimized implementation");

    let speedup_mean = stats_old.mean / stats_optimized.mean;
    let speedup_p95 = stats_old.p95 / stats_optimized.p95;
    println!("\nSpeedup:");
    println!("  Based on  mean (geom): {:.2}x", speedup_mean);
    println!("  Based on p95:          {:.2}x", speedup_p95);

    // Verify both methods return the same results
    let attrs_old = session.get_attributes_old(object, attributes)?;
    let attrs_optimized = session.get_attributes(object, attributes)?;

    println!("\nVerifying correctness...");
    println!(
        "  Original implementation returned {} attributes",
        attrs_old.len()
    );
    println!(
        "  Optimized implementation returned {} attributes",
        attrs_optimized.len()
    );

    if attrs_old.len() != attrs_optimized.len() {
        println!("  ✗ Implementations returned different number of attributes!");
    } else {
        println!("  ✓ Both implementations returned the same number of attributes");

        // Verify the order is the same
        let mut order_matches = true;
        for (i, (old_attr, opt_attr)) in attrs_old.iter().zip(attrs_optimized.iter()).enumerate() {
            if std::mem::discriminant(old_attr) != std::mem::discriminant(opt_attr) {
                println!(
                    "  ✗ Attribute at position {} differs: {:?} vs {:?}",
                    i, old_attr, opt_attr
                );
                order_matches = false;
            }
        }

        if order_matches {
            println!("  ✓ Attributes are in the same order");
        }
    }

    Ok(BenchmarkResult {
        label: label.to_string(),
        stats_old,
        stats_optimized,
    })
}

fn print_summary_table(results: &[BenchmarkResult]) {
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                  BENCHMARK SUMMARY TABLE                                          ║");
    println!("╠═══════════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═══════╦═══════════════╣");
    println!(
        "║ {:^17} ║ {:>11} ║ {:>11} ║ {:>11} ║ {:>11} ║ {:^5} ║ {:^13} ║",
        "Test Case", "Orig Mean", "Orig p95", "Opt Mean", "Opt p95", "Unit", "Speedup"
    );
    println!("╠═══════════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═══════╬═══════════════╣");

    // Each row is a test case
    for result in results {
        println!(
            "║ {:17} ║ {:11.2} ║ {:11.2} ║ {:11.2} ║ {:11.2} ║ {:>5} ║ {:>13} ║",
            result.label,
            result.stats_old.mean / 1000.0,
            result.stats_old.p95 / 1000.0,
            result.stats_optimized.mean / 1000.0,
            result.stats_optimized.p95 / 1000.0,
            "µs",
            format!("x {:.2}", result.speedup_mean())
        );
    }

    println!("╚═══════════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═══════╩═══════════════╝");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // how many iterations to run, default to 1000
    let iterations = env::var("TEST_BENCHMARK_ITERATIONS")
        .unwrap_or_else(|_| "1000".to_string())
        .parse::<usize>()?;

    let pkcs11 = Pkcs11::new(
        env::var("TEST_PKCS11_MODULE")
            .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string()),
    )?;

    let pin = env::var("TEST_PKCS11_PIN").unwrap_or_else(|_| "fedcba123456".to_string());
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    let nogenerate = env::var("TEST_PKCS11_NO_KEYGEN").is_ok();

    let slot = pkcs11
        .get_slots_with_token()?
        .into_iter()
        .next()
        .ok_or("No slot available")?;

    let session = pkcs11.open_rw_session(slot)?;

    session.login(UserType::User, Some(&AuthPin::new(pin.into())))?;

    let public;
    let _private;

    if nogenerate {
        // search for an elliptic curve public key.
        // if more than one, take the first that comes.
        println!("Using existing EC public key for benchmarking...");
        let template = vec![
            Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::EC),
        ];
        let objects = session.find_objects(&template)?;
        if objects.is_empty() {
            return Err(
                "No EC public key found on the token. Cannot proceed with benchmarks.".into(),
            );
        }
        public = objects[0];
    } else {
        // Generate a test EC key pair (P-256 curve)
        let mechanism = Mechanism::EccKeyPairGen;

        // ANSI X9.62 prime256v1 (P-256) curve OID: 1.2.840.10045.3.1.7
        let ec_params = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

        let pub_key_template = vec![
            Attribute::Token(false), // Don't persist
            Attribute::Private(false),
            Attribute::EcParams(ec_params),
            Attribute::Verify(true),
            Attribute::Label("Benchmark EC Key".into()),
            Attribute::Id(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        ];

        let priv_key_template = vec![Attribute::Token(false), Attribute::Sign(true)];

        println!("Generating EC key pair for benchmarking...");
        (public, _private) =
            session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;
    }

    let mut results = Vec::new();

    // Test 1: Multiple attributes (mix of fixed and variable length)
    let multiple_attributes = vec![
        AttributeType::Class,    // CK_ULONG (fixed, 8 bytes)
        AttributeType::Label,    // Variable length
        AttributeType::Id,       // Variable length
        AttributeType::KeyType,  // CK_ULONG (fixed, 8 bytes)
        AttributeType::Token,    // CK_BBOOL (c_uchar, 1 byte)
        AttributeType::Private,  // CK_BBOOL (c_uchar, 1 byte)
        AttributeType::EcPoint,  // Variable length (~65 bytes for P-256 uncompressed)
        AttributeType::EcParams, // Variable length (10 bytes for P-256 OID)
        AttributeType::Verify,   // CK_BBOOL (c_uchar, 1 byte)
        AttributeType::Encrypt,  // CK_BBOOL (c_uchar, 1 byte)
        AttributeType::Local,    // CK_BBOOL (c_uchar, 1 byte)
    ];

    results.push(benchmark_attributes(
        &session,
        public,
        &multiple_attributes,
        iterations,
        "Multiple",
    )?);

    // Test 2: Single fixed-length attribute (CK_ULONG)
    let single_fixed = vec![AttributeType::KeyType];

    results.push(benchmark_attributes(
        &session,
        public,
        &single_fixed,
        iterations,
        "Single-fixed",
    )?);

    // Test 3: Single variable-length attribute (EC point, ~65 bytes for P-256)
    let single_variable = vec![AttributeType::EcPoint];

    results.push(benchmark_attributes(
        &session,
        public,
        &single_variable,
        iterations,
        "Single-variable",
    )?);

    // Test 4: Single attribute that doesn't exist (Modulus for EC key)
    let single_nonexistent = vec![AttributeType::Modulus];

    results.push(benchmark_attributes(
        &session,
        public,
        &single_nonexistent,
        iterations,
        "Single-nonexist",
    )?);

    // Print summary table
    print_summary_table(&results);

    // Clean up
    if !nogenerate {
        session.destroy_object(public)?;
    }

    Ok(())
}
