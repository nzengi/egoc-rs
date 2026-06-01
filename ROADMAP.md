# egoc-rs — Production Roadmap

> Committee: A1 de Valence (RustCrypto), A2 O'Connor (BLAKE3), A3 Bowe (halo2),
> A4 Szalai (zkcrypto), A5 Bernstein (CT/perf), A6 Heninger (security),
> A7 Crichton (API), A8 Gallant (testing)

---

## Phase 0 — Academic Prototype ✅ (Completed)


| Item                                                  | Status |
| ----------------------------------------------------- | ------ |
| Rust workspace + 6-crate architecture                 | ✅      |
| `egoc-field`: Fq arithmetic, ct_pow Fermat inversion  | ✅      |
| `egoc-sl2`: SL(2,Fq) group, det invariant             | ✅      |
| `egoc-commit`: lift / commit / verify (constant-time) | ✅      |
| `egoc-proof`: Σ-protocol + Fiat-Shamir BLAKE3         | ✅      |
| `egoc-ivc`: Nova-style tree fold                      | ✅      |
| `egoc-bench`: Criterion + Throughput                  | ✅      |
| Critical timing fix: ct_pow, Choice accumulation      | ✅      |
| Modular bias fix: u128 reduction                      | ✅      |
| Security: Zeroize + ZeroizeOnDrop on all secret types | ✅      |
| 20/20 tests passing                                   | ✅      |


---

## Phase 1 — Hardening (0–3 Months)

### 1.1 Constant-Time Audit (A5 Bernstein — top priority)

- Formal CTGRIND / Valgrind memcheck verification for `ct_pow`
- `cargo-careful` + `miri` unsafe-free verification
- `dudect` side-channel test (correlation power analysis simulation)
- `random_fp` u128 bias → rejection sampling for zero-bias option

### 1.2 API Stabilization (A7 Crichton)

- `EgocError` unified error enum (`egoc-core` crate)
- `CommitMatrix::rows` → private + `rows()` accessor
- Builder pattern: `EgocParams { n, q }` passed to all functions
- Semantic versioning policy: `0.1.x` patch, `0.2.0` minor API breaks
- `#![deny(missing_docs)]` on all public APIs

### 1.3 Test Coverage Expansion (A8 Gallant)

- Property-based testing: `proptest` with random (m, r, g) triples
- Adversarial tests: binding/hiding negative test vectors
- 90%+ line coverage target with `cargo-llvm-cov`
- Fuzzing: `cargo-fuzz` targets for `commit`, `verify`, `verify_proof`

### 1.4 Security Hardening (A6 Heninger)

- `subtle::ConstantTimeGreater/Less` — eliminate all branches in comparisons
- Stack zeroing: `zeroize` scope guard on every `prove` call
- `no_std` compatibility: `alloc` feature flag, WASM/embedded readiness
- Panic-free `#![no_panic]` attribute (A5 request)

---

## Phase 2 — Performance Optimization (3–9 Months)

### 2.1 Montgomery Arithmetic (A4 Szalai + A5 Bernstein)

- `egoc-field`: `MontFp` type in Montgomery form
  - `REDC` algorithm: single reduction per multiplication
  - Switch to `const` generic parameter for compile-time fixed `q`
  - Target: 30–40% speedup for `mul`
- Comparison benchmarks against `ark-ff` / `ff` crates

### 2.2 SIMD / AVX2 Parallelization (A5 Bernstein)

- `egoc-field`: `std::arch` + `packed_simd2` for 4×u64 batch multiply
- `lift` map: SIMD row processing (4 rows at a time)
- `mat_mul_2x2`: SIMD 2×2 block matrix multiply
- ARM NEON support (Apple M-series)
- Target: commit < 100 ns for n=10

### 2.3 Parallel Folding (A3 Bowe)

- `tree_fold`: level-parallel fold with `rayon`
- `FoldResult`: zero-copy with `Arc<Witness>`
- Target: N=1024 tree fold < 10 ms (single thread), < 2 ms (8 threads)

### 2.4 BLAKE3 Optimization (A2 O'Connor)

- Domain separation with keyed BLAKE3: `blake3::keyed_hash`
- Streaming hashing: `blake3::Hasher` reuse for large matrices
- Target: Fiat-Shamir challenge < 50 ns

---

## Phase 3 — Ecosystem Integration (9–18 Months)

### 3.1 Halo2 Integration (A3 Bowe)

- `egoc-halo2` crate: implement `halo2_proofs::arithmetic::FieldExt`
- E-GOC commitment → Halo2 circuit gadget
- IVC fold integration with recursive SNARK

### 3.2 WASM / Mobile Targets (A7 Crichton)

- `wasm32-unknown-unknown` target: `getrandom` WASM backend
- `egoc-js`: `wasm-bindgen` TypeScript bindings
- Bundle size target: < 50 KB gzip

### 3.3 C Reference Implementation (NIST)

- C API header generation with `cbindgen`
- `egoc.h`: `egoc_commit`, `egoc_verify`, `egoc_prove`, `egoc_verify_proof`
- NIST post-quantum submission package preparation

### 3.4 Audit

- Trail of Bits / NCC Group security audit
- Formal verification: EasyCrypt `egoc_security_v9.ec` alignment with `egoc-rs`
- IETF Internet-Draft

---

## Commit Procedure

```
main          ← reviewed, CI green, audit approved only
├── dev       ← active development branch
│   ├── feat/montgomery-arithmetic
│   ├── feat/simd-field
│   ├── fix/ct-audit
│   └── feat/halo2-integration
└── release/v0.x.x
```

### Branch Naming

- `feat/<topic>` — new feature
- `fix/<topic>` — bug fix
- `perf/<topic>` — performance improvement
- `audit/<topic>` — security fix

---

## Performance Targets (end of Phase 2)


| Operation             | Current (Phase 0) | Target (Phase 2)   |
| --------------------- | ----------------- | ------------------ |
| commit n=10 q=257     | ~300 ns           | < 100 ns           |
| verify n=10 q=257     | ~370 ns           | < 120 ns           |
| nizkp_prove n=10      | ~2.0 µs           | < 700 ns           |
| nizkp_verify n=10     | ~1.9 µs           | < 600 ns           |
| ivc_fold n=10         | ~4.5 µs           | < 1.5 µs           |
| tree_fold N=1024 n=10 | ~46 ms            | < 2 ms (8 threads) |


