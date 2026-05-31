# egoc-rs

Rust implementation of **E-GOC** (Efficient Group-Orbit Commitment).

## Architecture (Committee: A1–A8)

```
egoc-rs/
├── crates/
│   ├── egoc-field    # Fq arithmetic, constant-time modinv  [D1]
│   ├── egoc-sl2      # SL(2,Fq) group, random sampling      [D2]
│   ├── egoc-commit   # lift / commit / verify + gauge hash   [D3]
│   ├── egoc-proof    # Sigma protocol + Fiat-Shamir BLAKE3   [D4]
│   ├── egoc-ivc      # Nova-style additive fold              [D5]
│   └── egoc-bench    # Criterion benchmarks                  [D6]
```

## Quick start

```bash
cargo test --workspace
cargo bench -p egoc-bench
```

## Security

- All secret types implement `zeroize::Zeroize` + `ZeroizeOnDrop`
- Constant-time comparisons via `subtle::ConstantTimeEq`
- Cross-gauge binding: `H(g) ≠ H(-g)` (BLAKE3 collision resistance)
- `rand::OsRng` for production randomness

## Hash instantiation

Reference implementation uses **BLAKE3** (5–10× faster than SHA-3, native XOF).
Security theorems are hash-agnostic; any NIST-approved collision-resistant
hash may be substituted.

## Author

nzengi