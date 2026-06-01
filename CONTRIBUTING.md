# Contributing Guide — egoc-rs

> This guide translates committee decisions (A1–A8) into coding standards.
> Every pull request must meet these standards before merge.

---

## Development Environment

```bash
# Rust stable (minimum 1.75.0)
rustup update stable
rustup component add clippy rustfmt llvm-tools-preview

# Cargo tools
cargo install cargo-careful cargo-llvm-cov cargo-fuzz

# Test
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

---

## Crate Ownership


| Crate         | Owner                         | Dependencies                       |
| ------------- | ----------------------------- | ---------------------------------- |
| `egoc-field`  | A5 DJB (CT), A4 Szalai (API)  | `subtle`, `zeroize`, `rand`        |
| `egoc-sl2`    | A1 de Valence                 | `egoc-field`, `subtle`, `zeroize`  |
| `egoc-commit` | A6 Heninger (security), A1    | `egoc-field`, `egoc-sl2`, `blake3` |
| `egoc-proof`  | A2 O'Connor (BLAKE3), A3 Bowe | `egoc-commit`, `egoc-proof`        |
| `egoc-ivc`    | A3 Bowe (folding)             | `egoc-proof`                       |
| `egoc-bench`  | A8 Gallant                    | all crates, `criterion`            |


---

## Coding Standards

### 1. Constant-Time Rules (A5 Bernstein — mandatory)

```rust
// WRONG — branch on secret data
if secret_val == 0 { return early; }

// CORRECT — accumulate with Choice, single bool at the end
let mut ok = Choice::from(1u8);
ok &= secret_val.ct_eq(&Fp::zero(q));
return bool::from(ok);
```

- Every secret comparison must use `subtle::ConstantTimeEq`
- Use `&` and `|` on `Choice` values instead of `&&` and `||`
- Use `ConditionallySelectable::conditional_select` instead of `if secret { ... }`
- Loop count must not depend on any secret value

### 2. Memory Safety (A6 Heninger — mandatory)

```rust
// Every struct holding secrets
#[derive(Zeroize, ZeroizeOnDrop)]
struct MySecret { ... }

// Temporary secret vectors
let mut tmp = vec![Fp::zero(q); n];
// ... use ...
tmp.iter_mut().for_each(|x| x.zeroize()); // before end of scope
```

- `Witness`, `Proof`, and every struct holding secrets must derive `ZeroizeOnDrop`
- `impl Debug` on secret structs must print `[REDACTED]` for secret fields

### 3. Random Sampling (A1 de Valence — mandatory)

```rust
// WRONG — modular bias
let v = rng.next_u64() % q;

// CORRECT — 128-bit reduction
let hi = rng.next_u64() as u128;
let lo = rng.next_u64() as u128;
let v = ((hi << 64 | lo) % q as u128) as u64;
```

- Use `OsRng` in production; use `StdRng::seed_from_u64` in tests
- RNG parameters must be constrained as `impl rand::RngCore + rand::CryptoRng`

### 4. Error Handling (A7 Crichton)

```rust
// WRONG — panic
let inv = a.invert().unwrap();

// CORRECT — propagate error
let inv = a.invert().ok_or(FieldError::NoInverse)?;

// Panic is only acceptable for public inputs — the name must make this explicit
let inv = public_val.inv_public();
```

### 5. Benchmark Requirements (A8 Gallant)

- Every new public function requires a benchmark in `egoc-bench`
- `Throughput::Elements(1)` must be added to every benchmark group
- Benchmark inputs must use `StdRng` with a fixed seed

---

## Pull Request Process

### Size Limit

- Max 400 lines changed per PR
- Large features must be split into smaller, reviewable PRs

### Checklist

```markdown
## PR Checklist
- [ ] `cargo test --workspace` passing
- [ ] `cargo clippy --workspace -- -D warnings` no warnings
- [ ] `cargo fmt --all --check` formatted
- [ ] New public functions have doc-comments
- [ ] Secret data derives Zeroize
- [ ] Comparisons use `subtle::ct_eq`
- [ ] Benchmark added (if applicable)
- [ ] ROADMAP.md updated (if applicable)
```

### Review Assignment


| Change Area                  | Required Reviewer |
| ---------------------------- | ----------------- |
| `egoc-field` arithmetic      | A5 (CT), A4 (API) |
| `egoc-sl2` group ops         | A1                |
| `egoc-commit` / `egoc-proof` | A6 (security)     |
| IVC / folding                | A3                |
| BLAKE3 usage                 | A2                |
| Any security fix             | A5 + A6           |


---

## Commit Message Format

```
<type>(<scope>): <summary>

[optional description]

[optional: Fixes #nnn]
```

Types: `feat`, `fix`, `perf`, `audit`, `test`, `docs`, `refactor`, `build`

Examples:

```
feat(egoc-field): ct_pow Fermat inversion replaces ext_gcd
fix(egoc-proof): ct_eq accumulation in verify_proof (A5)
perf(egoc-field): const-generic Fp<Q> removes per-element q field
audit(egoc-commit): constant-time gauge hash comparison
```

---

## Security Vulnerability Reporting

Do not open security vulnerabilities as public GitHub issues.
Send an encrypted (GPG) email to `security@egoc-rs.example.com`.

Response SLA: 48 hours.