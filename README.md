# egoc-rs

A post-quantum commitment scheme written in Rust. No trusted setup. No pairing-based cryptography. Security comes from a new algebraic problem over small finite fields.

---

## What it does

A commitment scheme lets you lock a secret message into a short value, then later prove you knew the message — without revealing it in advance. E-GOC does this using matrix groups over small prime fields instead of elliptic curves or lattices.

You commit to a message, get back a commitment matrix. Later you produce a zero-knowledge proof that you know the opening. A verifier checks the proof without ever seeing the message.

---

## Why it is different

Most commitment schemes rely on discrete logarithm hardness over large primes or elliptic curves. Shor's quantum algorithm breaks those.

E-GOC is built on the **Shadow Separation Problem** over **SL(2, Fq)** — a non-abelian matrix group. Non-abelian means `A·B ≠ B·A`, which puts it outside the reach of Shor's algorithm. The binding property is unconditional — it holds algebraically, not just computationally.

There is no trusted setup. Parameters are just two numbers: `n` (message length) and `q` (field prime).

---

## Security levels

| Level      | n  | q   | Security | Commitment | Proof    |
|------------|----|-----|----------|------------|----------|
| NIST I     | 10 | 257 | 136 bits | 320 bytes  | 496 bytes |
| NIST III   | 16 | 257 | 232 bits | 512 bytes  | 784 bytes |
| NIST V     | 22 | 257 | 328 bits | 704 bytes  | 1072 bytes |

Security formula: `(2n − 3) · ⌊log₂ q⌋` bits.

---

## Quick start

```bash
git clone https://github.com/nzengi/egoc-rs
cd egoc-rs

# Run all tests
cargo test --workspace

# Run the demo
cargo run --example demo -p egoc-bench

# Run benchmarks
cargo bench -p egoc-bench
```

---

## Demo output (actual values)

Running `cargo run --example demo -p egoc-bench` with NIST Level I parameters (`n=10, q=257`):

**Commitment** — message locked into a 20-row matrix:

```
Gauge g: a=189  b=53  c=197  d=111  (det=1)

C[ 0] = [ 205,  91 ]
C[ 1] = [  61, 254 ]
C[ 2] = [ 122,   8 ]
...
C[19] = [ 229, 182 ]

Gauge hash: 6f587b40d7844743e6e5496139cdad533845613e67c6d2f78d943990334b82df
Size: 320 bytes
```

**Zero-knowledge proof** — proves knowledge of the message, reveals nothing:

```
z_m = [169,  76, 110, 242, 125,   5,  88, 140,  72, 241]
z_r = [122,  14, 168, 136, 196, 250,  88, 143, 242, 243]
Size: 496 bytes

verify_proof → Ok  ✓
serialize → deserialize → verify → Ok  ✓
```

**Batch folding** — 8 commitments aggregated into one proof:

```
Tree depth:      3
All valid:       yes ✓
Soundness error: 3/257 ≈ 1.17%
Final proof:     496 bytes
```

**Known answer test** — deterministic vector for m=[1..10], r=[0..0], seed=0:

```
g = [[81, 249], [218, 245]]

C[ 0] = [ 81, 249 ]
C[ 1] = [ 39,  12 ]
...
C[19] = [133, 120 ]

Gauge hash: f025957d9694f379426b6b27fce00be5dab70c75fdb2032568d88e6d0c95b0be

commit verify → Ok  ✓
proof verify  → Ok  ✓
```

---

## How it works

A message `m` and randomness `r` are lifted into a matrix `L(m, r)` through a structured interleaving. That matrix is multiplied by a public gauge element `g ∈ SL(2, Fq)` to produce the commitment.

To prove knowledge without revealing `m`, the prover runs a three-move sigma protocol. The prover picks random blinding vectors, receives a challenge derived from BLAKE3, and responds with a linear combination. The verifier checks one matrix equation.

For batching, multiple commitments fold additively: `L(m₁+m₂, r₁+r₂)·g = C₁ + C₂`. This is a direct consequence of the lift map's linearity, not borrowed from any external system.

---

## Crate layout

```
egoc-rs/
├── crates/
│   ├── egoc-field    — field arithmetic over Fq, constant-time inverse
│   ├── egoc-sl2      — SL(2,Fq) group operations
│   ├── egoc-commit   — commit / verify
│   ├── egoc-proof    — zero-knowledge proof, serialization
│   ├── egoc-ivc      — fold and tree-fold
│   └── egoc-bench    — benchmarks and demo
```

All secret values are zeroed on drop. Comparisons use constant-time primitives throughout.

---

## Performance (NIST Level I, n=10, q=257)

| Operation      | Time     |
|----------------|----------|
| commit         | ~286 ns  |
| verify         | ~374 ns  |
| prove (NIZKP)  | ~2.36 µs |
| verify proof   | ~1.72 µs |
| fold (2→1)     | ~4.96 µs |
| tree fold N=8  | ~40 µs   |

Run `cargo bench -p egoc-bench` to get numbers on your machine.

---

## License

MIT OR Apache-2.0

## Author

nzengi