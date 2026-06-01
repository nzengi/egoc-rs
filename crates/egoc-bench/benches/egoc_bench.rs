// E-GOC Criterion benchmarks
// Updated: Phase 0 security fixes — ct_pow, u128 random, Choice verify
//
// Committee owners:
//   A5 Bernstein  — primitive / CT sections (field, sl2)
//   A2 O'Connor   — BLAKE3 sections (gauge_hash, fiat_shamir)
//   A1 de Valence — sampling sections (random_fp, random_sl2)
//   A8 Gallant    — benchmark structure, measurement config
//   A3 Bowe       — IVC / tree-fold scaling
//
// Run:  cargo bench -p egoc-bench
// HTML: target/criterion/

use std::time::Duration;

use criterion::{
    black_box, criterion_group, criterion_main,
    BatchSize, BenchmarkId, Criterion, Throughput,
};
use egoc_commit::{commit, gauge_hash, lift, verify, Witness};
use egoc_field::{random_fp, random_nonzero};
use egoc_ivc::{ivc_fold, tree_fold};
use egoc_proof::{fiat_shamir_challenge, prove, verify_proof};
use egoc_sl2::random_sl2;
use rand::SeedableRng;
use rand::rngs::StdRng;

// ---------------------------------------------------------------------------
// Parameter sets: (n, q, label)
//   n4_q101   — small / debug
//   n10_q257  — NIST Level I equivalent (primary target)
//   n16_q257  — mid-range
//   n24_q257  — heavy
// ---------------------------------------------------------------------------
const PARAMS: &[(usize, u64, &str)] = &[
    (4,  101, "n4_q101"),
    (10, 257, "n10_q257"),
    (16, 257, "n16_q257"),
    (24, 257, "n24_q257"),
];

// Tree-fold scaling: witness counts
const FOLD_SIZES: &[usize] = &[4, 8, 16, 32, 64, 128, 256];

// Fixed field / group params for primitive benchmarks
const PRIM_Q: u64   = 257;
const PRIM_N: usize = 10;

// ---------------------------------------------------------------------------
// Section 1 — Field primitives  (A5 Bernstein)
// After Phase-0 fix: invert uses ct_pow (Fermat), random_fp uses u128 reduction
// ---------------------------------------------------------------------------

fn bench_field_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("field");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);
    group.throughput(Throughput::Elements(1));

    let mut rng = StdRng::seed_from_u64(0);
    let a = random_nonzero(PRIM_Q, &mut rng);
    let b = random_nonzero(PRIM_Q, &mut rng);

    // Fp::add
    group.bench_function("add", |bench| {
        bench.iter(|| black_box(a).add(black_box(b)))
    });

    // Fp::mul
    group.bench_function("mul", |bench| {
        bench.iter(|| black_box(a).mul(black_box(b)))
    });

    // Fp::invert — ct_pow Fermat (was ext_gcd_inv, now constant-time)
    group.bench_function("invert_ct_pow", |bench| {
        bench.iter(|| black_box(a).invert())
    });

    // random_fp — u128 two-call reduction (was next_u64 % q)
    group.bench_function("random_fp_u128", |bench| {
        let mut rng2 = StdRng::seed_from_u64(1);
        bench.iter(|| random_fp(PRIM_Q, &mut rng2))
    });

    // random_nonzero
    group.bench_function("random_nonzero", |bench| {
        let mut rng2 = StdRng::seed_from_u64(2);
        bench.iter(|| random_nonzero(PRIM_Q, &mut rng2))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Section 2 — SL(2,Fq) group operations  (A5 Bernstein, A1 de Valence)
// ---------------------------------------------------------------------------

fn bench_sl2(c: &mut Criterion) {
    let mut group = c.benchmark_group("sl2");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(400);
    group.throughput(Throughput::Elements(1));

    let mut rng = StdRng::seed_from_u64(10);
    let g = random_sl2(PRIM_Q, &mut rng);
    let h = random_sl2(PRIM_Q, &mut rng);

    // Group multiply
    group.bench_function("mul", |bench| {
        bench.iter(|| black_box(g).mul(black_box(&h)))
    });

    // Group inverse
    group.bench_function("inverse", |bench| {
        bench.iter(|| black_box(g).inverse())
    });

    // Negate (cross-gauge attack defence: -g)
    group.bench_function("neg", |bench| {
        bench.iter(|| black_box(g).neg())
    });

    // Serialise to bytes (used in BLAKE3 hashing)
    group.bench_function("to_bytes", |bench| {
        bench.iter(|| black_box(g).to_bytes())
    });

    // Sample a random element (rejection sampling)
    group.bench_function("random_sl2", |bench| {
        let mut rng2 = StdRng::seed_from_u64(11);
        bench.iter(|| random_sl2(PRIM_Q, &mut rng2))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Section 3 — BLAKE3 operations  (A2 O'Connor)
// gauge_hash: H(g) — cross-gauge binding
// fiat_shamir_challenge: u128 reduction (was u64)
// ---------------------------------------------------------------------------

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(400);
    group.throughput(Throughput::Elements(1));

    let mut rng = StdRng::seed_from_u64(20);
    let g   = random_sl2(PRIM_Q, &mut rng);
    let w   = Witness::random(PRIM_N, PRIM_Q, &mut rng);
    let cmt = commit(&w, &g);
    let pf  = prove(&w, &g, &cmt.matrix, &mut rng);

    // gauge_hash — BLAKE3(g.to_bytes())
    group.bench_function("gauge_hash", |bench| {
        bench.iter(|| gauge_hash(black_box(&g)))
    });

    // fiat_shamir_challenge — q derived from CommitMatrix (no raw q param)
    group.bench_function("fiat_shamir_u128", |bench| {
        bench.iter(|| {
            fiat_shamir_challenge(
                black_box(&cmt.matrix),
                black_box(&g),
                black_box(&pf.a_rows),
            )
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Section 4 — Lift map  (A1 de Valence, A4 Szalai)
// L(m,r) ∈ Fq^{2n×2} — isolated from commit to measure layout cost
// ---------------------------------------------------------------------------

fn bench_lift(c: &mut Criterion) {
    let mut group = c.benchmark_group("lift");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(300);
    group.throughput(Throughput::Elements(1));

    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(30);
        let w = Witness::random(n, q, &mut rng);
        group.bench_with_input(BenchmarkId::new("lift", label), label, |b, _| {
            b.iter(|| lift(black_box(&w)))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Section 5 — Commit / Verify  (A6 Heninger, A1 de Valence)
// verify: now fully constant-time via Choice accumulation (Phase-0 fix)
// ---------------------------------------------------------------------------

fn bench_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);
    group.throughput(Throughput::Elements(1));

    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(40);
        let w = Witness::random(n, q, &mut rng);
        let g = random_sl2(q, &mut rng);
        group.bench_with_input(BenchmarkId::new("commit", label), label, |b, _| {
            b.iter(|| commit(black_box(&w), black_box(&g)))
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);
    group.throughput(Throughput::Elements(1));

    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(41);
        let w   = Witness::random(n, q, &mut rng);
        let g   = random_sl2(q, &mut rng);
        let cmt = commit(&w, &g);
        group.bench_with_input(BenchmarkId::new("verify", label), label, |b, _| {
            b.iter(|| verify(black_box(&w), black_box(&g), black_box(&cmt)))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Section 6 — NIZKP Prove / Verify  (A2 O'Connor, A3 Bowe, A5 Bernstein)
// verify_proof: now uses Choice accumulation — no short-circuit (Phase-0 fix)
// ---------------------------------------------------------------------------

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizkp_prove");
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(50);
        let w   = Witness::random(n, q, &mut rng);
        let g   = random_sl2(q, &mut rng);
        let cmt = commit(&w, &g);
        group.bench_with_input(BenchmarkId::new("prove", label), label, |b, _| {
            let mut rng2 = StdRng::seed_from_u64(99);
            b.iter(|| prove(black_box(&w), black_box(&g), black_box(&cmt.matrix), &mut rng2))
        });
    }
    group.finish();
}

fn bench_verify_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizkp_verify");
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(51);
        let w   = Witness::random(n, q, &mut rng);
        let g   = random_sl2(q, &mut rng);
        let cmt = commit(&w, &g);
        let pf  = prove(&w, &g, &cmt.matrix, &mut rng);
        group.bench_with_input(BenchmarkId::new("verify_proof", label), label, |b, _| {
            b.iter(|| verify_proof(black_box(&cmt.matrix), black_box(&g), black_box(&pf)))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Section 7 — IVC Single Fold  (A3 Bowe)
// ---------------------------------------------------------------------------

fn bench_fold(c: &mut Criterion) {
    let mut group = c.benchmark_group("ivc_fold");
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(60);
        let w1 = Witness::random(n, q, &mut rng);
        let w2 = Witness::random(n, q, &mut rng);
        let g  = random_sl2(q, &mut rng);
        group.bench_with_input(BenchmarkId::new("fold", label), label, |b, _| {
            let mut rng2 = StdRng::seed_from_u64(77);
            b.iter(|| ivc_fold(black_box(&w1), black_box(&w2), black_box(&g), &mut rng2))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Section 8 — Tree Fold Scaling  (A3 Bowe)
// N = 4, 8, 16, 32, 64 witnesses — shows O(n·log N) scaling
// Uses iter_batched to avoid measuring witness clone overhead
// ---------------------------------------------------------------------------

fn bench_tree_fold_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_fold_scaling");
    group.measurement_time(Duration::from_secs(8));
    group.sample_size(50);

    let q = PRIM_Q;
    let n = PRIM_N;

    for &size in FOLD_SIZES {
        let label = format!("N{}_n{}_q{}", size, n, q);
        let mut rng = StdRng::seed_from_u64(70);
        let g = random_sl2(q, &mut rng);
        let witnesses: Vec<Witness> = (0..size)
            .map(|_| Witness::random(n, q, &mut rng))
            .collect();

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("tree_fold", &label),
            &label,
            |b, _| {
                b.iter_batched(
                    || witnesses.clone(),
                    |ws| {
                        let mut rng2 = StdRng::seed_from_u64(88);
                        tree_fold(black_box(ws), black_box(&g), &mut rng2)
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    // Section 1 — primitives
    bench_field_primitives,
    bench_sl2,
    // Section 2 — BLAKE3
    bench_blake3,
    // Section 3 — lift
    bench_lift,
    // Section 4 — commit/verify
    bench_commit,
    bench_verify,
    // Section 5 — NIZKP
    bench_prove,
    bench_verify_proof,
    // Section 6 — IVC
    bench_fold,
    bench_tree_fold_scaling,
);
criterion_main!(benches);