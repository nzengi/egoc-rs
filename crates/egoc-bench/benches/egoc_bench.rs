// E-GOC Criterion benchmarks
// Updated: Fp<Q> const-generic refactor
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
use egoc_field::{random_fp, random_nonzero, Fp};
use egoc_ivc::{ivc_fold, tree_fold};
use egoc_proof::{fiat_shamir_challenge, prove, verify_proof};
use egoc_sl2::{random_sl2, SL2};
use rand::SeedableRng;
use rand::rngs::StdRng;

// ---------------------------------------------------------------------------
// Parameter sets: (n, label)
//   All use Q=257 — the standard EGOC prime for Level I/III/V.
// ---------------------------------------------------------------------------
const Q: u64 = 257;

// (n, label) pairs — Q is fixed as a const generic
const PARAMS_N: &[(usize, &str)] = &[
    (4,  "n4_q257"),
    (10, "n10_q257"),
    (16, "n16_q257"),
    (24, "n24_q257"),
];

// Tree-fold scaling: witness counts
const FOLD_SIZES: &[usize] = &[4, 8, 16, 32, 64, 128, 256];

// Fixed n for primitive benchmarks
const PRIM_N: usize = 10;

// ---------------------------------------------------------------------------
// Section 1 — Field primitives  (A5 Bernstein)
// ---------------------------------------------------------------------------

fn bench_field_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("field");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);
    group.throughput(Throughput::Elements(1));

    let mut rng = StdRng::seed_from_u64(0);
    let a: Fp<Q> = random_nonzero(&mut rng);
    let b: Fp<Q> = random_nonzero(&mut rng);

    group.bench_function("add", |bench| {
        bench.iter(|| black_box(a).add(black_box(b)))
    });

    group.bench_function("mul", |bench| {
        bench.iter(|| black_box(a).mul(black_box(b)))
    });

    group.bench_function("invert_ct_pow", |bench| {
        bench.iter(|| black_box(a).invert())
    });

    group.bench_function("random_fp_u128", |bench| {
        let mut rng2 = StdRng::seed_from_u64(1);
        bench.iter(|| random_fp::<Q>(&mut rng2))
    });

    group.bench_function("random_nonzero", |bench| {
        let mut rng2 = StdRng::seed_from_u64(2);
        bench.iter(|| random_nonzero::<Q>(&mut rng2))
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
    let g: SL2<Q> = random_sl2(&mut rng);
    let h: SL2<Q> = random_sl2(&mut rng);

    group.bench_function("mul", |bench| {
        bench.iter(|| black_box(g).mul(black_box(&h)))
    });

    group.bench_function("inverse", |bench| {
        bench.iter(|| black_box(g).inverse())
    });

    group.bench_function("neg", |bench| {
        bench.iter(|| black_box(g).neg())
    });

    group.bench_function("to_bytes", |bench| {
        bench.iter(|| black_box(g).to_bytes())
    });

    group.bench_function("random_sl2", |bench| {
        let mut rng2 = StdRng::seed_from_u64(11);
        bench.iter(|| random_sl2::<Q>(&mut rng2))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Section 3 — BLAKE3 operations  (A2 O'Connor)
// ---------------------------------------------------------------------------

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(400);
    group.throughput(Throughput::Elements(1));

    let mut rng = StdRng::seed_from_u64(20);
    let g: SL2<Q>  = random_sl2(&mut rng);
    let w: Witness<Q> = Witness::random(PRIM_N, &mut rng);
    let cmt = commit(&w, &g);
    let pf  = prove(&w, &g, &cmt.matrix, &mut rng);

    group.bench_function("gauge_hash", |bench| {
        bench.iter(|| gauge_hash(black_box(&g)))
    });

    group.bench_function("fiat_shamir_u128", |bench| {
        bench.iter(|| {
            fiat_shamir_challenge(
                black_box(&cmt.matrix),
                black_box(&g),
                black_box(&pf.a),
            )
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Section 4 — Lift map  (A1 de Valence, A4 Szalai)
// ---------------------------------------------------------------------------

fn bench_lift(c: &mut Criterion) {
    let mut group = c.benchmark_group("lift");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(300);
    group.throughput(Throughput::Elements(1));

    for &(n, label) in PARAMS_N {
        let mut rng = StdRng::seed_from_u64(30);
        let w: Witness<Q> = Witness::random(n, &mut rng);
        group.bench_with_input(BenchmarkId::new("lift", label), label, |b, _| {
            b.iter(|| lift(black_box(&w)))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Section 5 — Commit / Verify  (A6 Heninger, A1 de Valence)
// ---------------------------------------------------------------------------

fn bench_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);
    group.throughput(Throughput::Elements(1));

    for &(n, label) in PARAMS_N {
        let mut rng = StdRng::seed_from_u64(40);
        let w: Witness<Q> = Witness::random(n, &mut rng);
        let g: SL2<Q>     = random_sl2(&mut rng);
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

    for &(n, label) in PARAMS_N {
        let mut rng = StdRng::seed_from_u64(41);
        let w: Witness<Q> = Witness::random(n, &mut rng);
        let g: SL2<Q>     = random_sl2(&mut rng);
        let cmt = commit(&w, &g);
        group.bench_with_input(BenchmarkId::new("verify", label), label, |b, _| {
            b.iter(|| verify(black_box(&w), black_box(&g), black_box(&cmt)))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Section 6 — NIZKP Prove / Verify  (A2 O'Connor, A3 Bowe, A5 Bernstein)
// ---------------------------------------------------------------------------

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizkp_prove");
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    for &(n, label) in PARAMS_N {
        let mut rng = StdRng::seed_from_u64(50);
        let w: Witness<Q> = Witness::random(n, &mut rng);
        let g: SL2<Q>     = random_sl2(&mut rng);
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

    for &(n, label) in PARAMS_N {
        let mut rng = StdRng::seed_from_u64(51);
        let w: Witness<Q> = Witness::random(n, &mut rng);
        let g: SL2<Q>     = random_sl2(&mut rng);
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

    for &(n, label) in PARAMS_N {
        let mut rng = StdRng::seed_from_u64(60);
        let w1: Witness<Q> = Witness::random(n, &mut rng);
        let w2: Witness<Q> = Witness::random(n, &mut rng);
        let g:  SL2<Q>     = random_sl2(&mut rng);
        group.bench_with_input(BenchmarkId::new("fold", label), label, |b, _| {
            let mut rng2 = StdRng::seed_from_u64(77);
            b.iter(|| ivc_fold(black_box(&w1), black_box(&w2), black_box(&g), &mut rng2))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Section 8 — Tree Fold Scaling  (A3 Bowe)
// ---------------------------------------------------------------------------

fn bench_tree_fold_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_fold_scaling");
    group.measurement_time(Duration::from_secs(8));
    group.sample_size(50);

    for &size in FOLD_SIZES {
        let label = format!("N{}_n{}_q{}", size, PRIM_N, Q);
        let mut rng = StdRng::seed_from_u64(70);
        let g: SL2<Q> = random_sl2(&mut rng);
        let witnesses: Vec<Witness<Q>> = (0..size)
            .map(|_| Witness::random(PRIM_N, &mut rng))
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
    bench_field_primitives,
    bench_sl2,
    bench_blake3,
    bench_lift,
    bench_commit,
    bench_verify,
    bench_prove,
    bench_verify_proof,
    bench_fold,
    bench_tree_fold_scaling,
);
criterion_main!(benches);