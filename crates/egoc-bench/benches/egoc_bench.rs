// E-GOC Criterion benchmarks  (Committee: A8 Gallant)
// Run: cargo bench -p egoc-bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use egoc_commit::{commit, verify, Witness};
use egoc_ivc::ivc_fold;
use egoc_proof::{prove, verify_proof};
use egoc_sl2::random_sl2;
use rand::SeedableRng;
use rand::rngs::StdRng;

// Parameters: (n, q, label)
const PARAMS: &[(usize, u64, &str)] = &[
    (4,  101, "n4_q101"),
    (10, 257, "n10_q257"),
    (16, 257, "n16_q257"),
    (24, 257, "n24_q257"),
];

fn bench_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(42);
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
    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(1);
        let w   = Witness::random(n, q, &mut rng);
        let g   = random_sl2(q, &mut rng);
        let cmt = commit(&w, &g);
        group.bench_with_input(BenchmarkId::new("verify", label), label, |b, _| {
            b.iter(|| verify(black_box(&w), black_box(&g), black_box(&cmt)))
        });
    }
    group.finish();
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("nizkp_prove");
    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(2);
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
    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(3);
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

fn bench_fold(c: &mut Criterion) {
    let mut group = c.benchmark_group("ivc_fold");
    for &(n, q, label) in PARAMS {
        let mut rng = StdRng::seed_from_u64(4);
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

criterion_group!(benches, bench_commit, bench_verify, bench_prove, bench_verify_proof, bench_fold);
criterion_main!(benches);