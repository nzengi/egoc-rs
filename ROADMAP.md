# egoc-rs — Production Roadmap

> Committee: A1 de Valence (RustCrypto), A2 O'Connor (BLAKE3), A3 Bowe (halo2),
> A4 Szalai (zkcrypto), A5 Bernstein (CT/perf), A6 Heninger (security),
> A7 Crichton (API), A8 Gallant (testing)

---

## Phase 0 — Academic Prototype (Completed) ✅


| Item                                                  | Status |
| ----------------------------------------------------- | ------ |
| Rust workspace + 6-crate architecture                 | ✅      |
| `egoc-field`: Fq arithmetic, ct_pow Fermat inversion  | ✅      |
| `egoc-sl2`: SL(2,Fq) group, det invariant             | ✅      |
| `egoc-commit`: lift / commit / verify (constant-time) | ✅      |
| `egoc-proof`: Σ-protocol + Fiat-Shamir BLAKE3         | ✅      |
| `egoc-ivc`: additive tree fold (L-linearity native)   | ✅      |
| `egoc-bench`: Criterion + Throughput                  | ✅      |
| Critical timing fix: ct_pow, Choice accumulation      | ✅      |
| Modular bias fix: u128 reduction                      | ✅      |
| Security: Zeroize + ZeroizeOnDrop on all secret types | ✅      |
| BLAKE3 domain separation: new_keyed                   | ✅      |
| CommitMatrix::rows private + accessor                 | ✅      |
| EgocParams::validate() + security_bits()              | ✅      |
| Proof::to_bytes / from_bytes                          | ✅      |
| hvzk_simulate() — HVZK audit tool                     | ✅      |
| 34/34 tests passing                                   | ✅      |


---

## Phase 1 — Hardening (0–3 Months)

### 1.1 Constant-Time Audit (A5 Bernstein — top priority)

- Formal CTGRIND / Valgrind memcheck verification for `ct_pow`
- `cargo-careful` + `miri` unsafe-free verification
- `dudect` side-channel test — verify ct_pow timing variance < 1%
- `random_fp` u128 bias → rejection sampling for zero-bias option

### 1.2 API Stabilization (A7 Crichton)

- `EgocError` unified error enum (`egoc-core` crate)
- Builder pattern: `EgocParams { n, q }` passed to all top-level functions
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

### 2.1 Field Arithmetic Optimization (A4 Szalai + A5 Bernstein)

> **Montgomery form does NOT apply to E-GOC.**
> E-GOC uses small primes (q <= 257, 8-bit modulus). The native
> `(a as u128 * b as u128) % q` is already a single CPU instruction.
> Montgomery REDC setup cost exceeds its savings at this scale.
> E-GOC hardness is based on SSP over SL(2,Fq), not discrete logarithm —
> large-prime field tricks from DLP-based schemes are irrelevant here.

- `Fp<const Q: u64>` const-generic: remove `q: u64` from each struct field
  - Halves struct size: 16 bytes → 8 bytes per element
  - Compiler folds `% Q` into immediate-mode division at compile time
  - Target: 10–15% commit speedup from reduced cache pressure
- Precomputed inverse table for q <= 2^10: `[u16; q]` static lookup
- Barrett reduction for q in range 2^16..2^32 (cheaper than u128 divide)
- Benchmark: const-generic `Fp<257>` vs runtime `Fp { q: 257 }`

### 2.2 SIMD / AVX2 Parallelization (A5 Bernstein)

- `egoc-field`: `std::arch` + `packed_simd2` for 4×u64 batch multiply
- `lift` map: SIMD row processing (4 rows at a time)
- `mat_mul_2x2`: SIMD 2×2 block matrix multiply
- ARM NEON support (Apple M-series)
- Target: commit < 100 ns for n=10

### 2.3 Parallel Folding (A3 Bowe)

> `**Arc<Witness>` does NOT apply to E-GOC.**
> Arc reference counting is a pattern from Groth16/Halo2 trusted-setup
> ceremonies where a large witness is shared across multiple parties.
> E-GOC has no trusted setup. The witness (m, r) is the user's own secret —
> it is never shared, there is no ceremony, no multi-party computation.

- `tree_fold`: level-parallel fold with `rayon` (independent pairs per level)
- Drop intermediate witnesses after each fold level to reduce peak memory
- Target: N=1024 tree fold < 10 ms (single thread), < 2 ms (8 threads)

### 2.4 BLAKE3 Optimization (A2 O'Connor)

- Domain separation with keyed BLAKE3: `blake3::new_keyed` ✅ done
- Streaming hashing: `blake3::Hasher` reuse for large matrices
- Target: Fiat-Shamir challenge < 50 ns

---

## Phase 3 — Ecosystem Integration (9–18 Months)

### 3.1 Compact Proof via External SNARK (Optional / Research)

> E-GOC already has its own IVC fold — wrapping it *inside* Nova or Halo2
> as a folding step is circular. E-GOC IS the folding scheme.
>
> The only meaningful use of an external SNARK is compressing a batch of
> E-GOC proofs into a single short proof. This requires encoding E-GOC's
> verify equation as a circuit — expensive over SL(2,Fq) small primes since
> Groth16/Plonk target large-prime BN254/BLS12-381 fields.
> Not a priority until E-GOC reaches production stability.

- Feasibility study: cost of SL(2,Fq) verify as R1CS over BN254
- Evaluate: Bulletproofs-style batch-verify (no trusted setup, small-field friendly)
- Decision gate: only proceed if batch-verify speedup > 10× at N=1024

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

## Phase 4 — Foundational Research (Open-Ended)

> These are not engineering tasks. They are open research questions
> specific to E-GOC's algebraic structure. No external framework applies.
> Progress here would constitute original cryptographic contributions.

### 4.1 Algebraic Non-Interactivity — Native Fiat-Shamir Alternative

> **Motivation.** Fiat-Shamir + BLAKE3 is a general technique: it works
> for *any* Sigma protocol by replacing the verifier's challenge with a
> hash. It is not derived from E-GOC's algebra. The question is whether
> SL(2,Fq)'s own algebraic invariants can produce the challenge —
> eliminating the hash oracle entirely and yielding a **purely algebraic,
> hash-free NIZKP** native to non-abelian group-orbit commitments.

**Research questions:**

- **Trace-based challenge:** Can `e = tr(L(m,r)·g) mod q` serve as a
sound non-interactive challenge? Threat: can a prover bias `k_m, k_r`
to control `tr(A + e·C)` before committing? Formal analysis required.
- **Commutator-based challenge:** Can `e = tr([L(m,r), g]) mod q`
(the commutator trace, measuring non-commutativity) be used?
This is intrinsic to the non-abelian structure of SL(2,Fq) — no hash needed.
- **SSP shadow coordinate as oracle:** The shadow map σ: SL(2,Fq) → Fq
is deterministic and hard to invert. Can σ(L(m,r)·g) function as a
one-way challenge without a ROM assumption?
- **Security model:** If algebraic challenge works, what replaces ROM?
Does non-abelian hardness of SSP provide a native soundness argument?
- **EasyCrypt:** Mechanise the new soundness proof; compare to existing
ROM lemmas in `egoc_security_v9.ec`.

**Success criterion:** A provably sound NIZKP for E-GOC with no hash
function and no random oracle assumption — soundness derived purely from
SSP hardness over SL(2,Fq).

**If successful:** This would be the first hash-free, purely algebraic
non-interactive ZK proof over a non-abelian group. A qualitatively
different result from all existing SNARK/STARK constructions.

---

### 4.2 Conjugation-Based Non-Abelian Sigma Protocol

> **Motivation.** The current Sigma protocol uses F_q additive responses
> (`z = k + e·m`). SL(2,Fq)'s non-abelian structure appears only in the
> binding — not in the proof mechanism itself. Conjugation homomorphism
> (`g·(K·W)·g⁻¹ = (g·K·g⁻¹)·(g·W·g⁻¹)`) enables a Sigma protocol
> where the response is a group multiplication, not a field addition.
> This would make E-GOC's ZK proof native to SL(2,Fq) multiplication.
>
> **Committee verdict (A1, A4, A6):** Mathematically feasible for CSP
> (Conjugacy Search Problem). However, three risks must be resolved first.

**Commutator Challenge Simulation Results (2026-06-02):**

Simulation over q=101, 10000 samples tested `e = trace([g,h]) mod q` as a
challenge function (see `egoc-rs/research_notes.md` for full output):

- `trace([g,h])` produces all q distinct values — valid challenge range ✓
- Distribution is NOT perfectly uniform: χ²=296 vs expected ~100, max bias 1.98x
- P[trace([g,h]) = target] ≈ 1/q per random h — soundness error matches Fiat-Shamir
- Adversary cannot fix a target trace without ≈q samples — not efficiently predictable

**Protocol sketch (hash-free Sigma):**
```
Setup:  C = L(m,r)·g  (public)
R1:     Prover picks k,s; A = L(k,s)·g; picks h ← SL(2,Fq); sends (A, h)
Chall:  e = trace(g·h·g⁻¹·h⁻¹) mod q  [deterministic, no hash]
R3:     z_m = k + e·m, z_r = s + e·r
Verify: L(z_m,z_r)·g = A + e·C
```

**Critical binding problem identified:** Prover chooses h after committing A.
If prover sees A first, they can sample h values to fix e to a chosen target
(requiring ~q samples). This breaks soundness.
Mitigation: bind h into the first round — e.g. send `(A, H(h))` before
revealing h, or use `A = L(k,s)·g·h` to embed h algebraically in the commitment.
The second option reintroduces h as an algebraic component — no hash needed
for the challenge itself, only for the commitment binding.

**Open problems:**
- Is the trace distribution bias cryptographically significant? Formal analysis needed.
- Does the h-binding solution preserve zero-knowledge?
- Reduction: is trace([g,h]) unpredictability reducible to SSP or DLP in SL(2,Fq)?

**Research questions:**

- **Linear representation attack resistance:** SL(2,Fq) has short
linear representations — do Lim–Lee or similar attacks break CSP
at small q? Empirical test at q=101, q=257, q=65537.
- **SSP vs CSP:** Current E-GOC hardness is SSP (shadow separation).
CSP (conjugacy search) is a different problem. Are they equivalent
over SL(2,Fq)? Can SSP reduce to CSP or vice versa?
- **Commitment redesign:** CSP-based ZK requires witness `W ∈ SL(2,Fq)`,
commitment `C = g·W·g⁻¹`. Current E-GOC witness is `(m,r) ∈ Fq^n × Fq^n`.
What is the map from `(m,r)` to a group element? Does L(m,r) work?
- **Binary challenge soundness:** Conjugation Sigma gives soundness `1/2`
per round. To reach 128-bit security without a hash: 128 rounds.
Is this acceptable, or does it require a large challenge space solution?

**Prerequisite for 4.3:** Results from CSP security analysis feed into 4.3.

---

### 4.3 Large Challenge Space Non-Abelian ZK

> **Motivation.** The binary challenge limitation of conjugation Sigma
> (§4.2) collapses soundness to `1/2` per round. E-GOC currently achieves
> `1/q` soundness with a single round using F_q challenge space. The
> question is whether a non-abelian group response can be combined with
> a large (`|Fq|`-sized) challenge space without falling back to additive
> field arithmetic for the response.
>
> **Committee verdict (A2, A3, A5):** Open problem. No known construction
> achieves both simultaneously. Binary challenge is the natural limit of
> group-multiplicative responses. Solving this would be a fundamental
> result in non-abelian ZK theory.

**Research questions:**

- **Algebraic challenge + group response:** Can challenge `e ∈ Fq`
(large space) be combined with response `Z = K · W^e ∈ SL(2,Fq)`?
Verification equation: what does `g·(K·W^e)·g⁻¹ = A · C^e` require
in terms of commutativity? Does non-abelian structure break it?
- **Partial non-abelian:** Response `(Z_group, z_field)` — group
component for gauge, field component for witness scalars. Hybrid:
non-abelian where SL(2,Fq) acts, additive where F_q acts. Is this
a meaningful improvement over the current pure-additive approach?
- **Performance bound:** Group exponentiation `W^e` for `e ∈ Fq`
costs `O(log q)` SL(2,Fq) multiplications. At q=257: ~8 multiplications.
Compare to current single F_q multiply. Is the overhead acceptable?
- **New security model:** If this works, the proof is no longer in
the Fiat-Shamir paradigm. What security model captures it?
Standard model? Generic group model?

**Success criterion:** A single-round ZK proof for E-GOC where both the
challenge space is `|Fq|` AND the response uses SL(2,Fq) group operations.
If achieved: proof mechanism and binding mechanism live in the same
non-abelian algebraic world — E-GOC becomes fully native end-to-end.

---

## Commit Procedure

```
main          <- reviewed, CI green, audit approved only
├── dev       <- active development branch
│   ├── feat/const-generic-field
│   ├── feat/simd-field
│   ├── fix/ct-audit
│   └── feat/rayon-tree-fold
└── release/v0.x.x
```

### Branch Naming

- `feat/<topic>` — new feature
- `fix/<topic>` — bug fix
- `perf/<topic>` — performance improvement
- `audit/<topic>` — security fix

---

## Performance Targets (end of Phase 2)


| Operation             | Current (Phase 1) | Target (Phase 2)   |
| --------------------- | ----------------- | ------------------ |
| commit n=10 q=257     | ~286 ns           | < 100 ns           |
| verify n=10 q=257     | ~374 ns           | < 120 ns           |
| nizkp_prove n=10      | ~2.36 µs          | < 700 ns           |
| nizkp_verify n=10     | ~1.72 µs          | < 600 ns           |
| ivc_fold n=10         | ~4.96 µs          | < 1.5 µs           |
| tree_fold N=1024 n=10 | ~5.4 ms (est.)    | < 2 ms (8 threads) |


