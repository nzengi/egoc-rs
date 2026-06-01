# egoc-auction

A sealed-bid auction built on the E-GOC commitment scheme.

This is an example project showing how E-GOC's cryptographic properties map
to a real-world use case. Each bidder commits to a secret bid amount. The
commitment is public and binding — no one can change their bid after the fact.
When the auction closes, the winner produces a zero-knowledge proof that they
hold the winning bid, without revealing any other bidder's amount.

---

## What it demonstrates

E-GOC provides four properties that sealed-bid auctions need:

**Binding** — Once a bidder submits a commitment, they cannot change the
amount behind it. This is unconditional in E-GOC: it holds algebraically,
not just under a computational assumption. A bidder cannot retroactively
claim they bid higher.

**Hiding** — The commitment reveals nothing about the bid amount. No
participant, including the auctioneer, can learn any bid during the bidding
phase. Bids become known only when explicitly revealed.

**Zero-knowledge proof** — The winner proves they hold the opening to the
winning commitment — without showing their bid amount to anyone who should
not see it. The proof is 496 bytes for NIST Level I parameters (n=10, q=257).

**IVC fold** — All participant commitments fold into a single aggregate
commitment. A verifier can check participation of all N bidders by verifying
one folded structure instead of N individual commitments.

---

## How to run

```bash
# From egoc-rs workspace root:
cargo run -p egoc-auction
```

---

## Example output

```
══════════════════════════════════════════════════════════════
  E-GOC Sealed-Bid Auction
  Binding · Hiding · ZK Proof · IVC Fold
══════════════════════════════════════════════════════════════

§1. Auction Setup
  Security: NIST Level I — n=10, q=257
  Security bits: 136 bits
  Public gauge g = [[189, 53], [197, 111]]  (det=1)

  Property: binding is UNCONDITIONAL — no bidder can
  change their bid after committing, even with unlimited compute.

§2. Bidding Phase  (commitments hidden from each other)
  Alice bids 142 units:
    Commitment C[0] = [153,  32]
    Bid amount  = [HIDDEN — only Alice knows]
  Bob bids 98 units:
    Commitment C[0] = [174, 228]
    Bid amount  = [HIDDEN — only Bob knows]
  Carol bids 213 units:
    Commitment C[0] = [175,  91]
    Bid amount  = [HIDDEN — only Carol knows]

§3. Winner Determination
    Alice : 142 units
    Bob   : 98 units
    Carol : 213 units ← WINNER

§4. Zero-Knowledge Proof
  verify_proof(Carol)  → Ok  ✓
  Impersonation attempt (Alice → Carol)  → rejected  ✓

§5. IVC Fold
  Fold valid:     yes ✓
  Property:       L(m₁+m₂+m₃, r₁+r₂+r₃)·g = C₁+C₂+C₃  ✓

§6. Binding Guarantee
  Bob's forgery attempt (claiming 213 units)  → rejected  ✓

  Auction Complete
  Winner:   Carol (213 units)
  Proof:    496 bytes
  Security: 136 bits (NIST Level I)
```

---

## API

```rust
use egoc_auction::Auction;
use egoc::{EgocParams};

let mut rng = StdRng::seed_from_u64(0);
let mut auction = Auction::<257>::new(EgocParams::LEVEL1, &mut rng);

// Each bidder submits a commitment — amount is hidden
auction.submit_bid("Alice", 142, &mut rng);
auction.submit_bid("Bob",   98,  &mut rng);
auction.submit_bid("Carol", 213, &mut rng);

// Auctioneer finds the winner by comparing revealed amounts
let winner = auction.find_winner().unwrap();

// Winner generates a ZK proof of the winning bid
let proof = auction.prove_winner(winner, &mut rng);

// Anyone can verify the proof against the public commitment
assert!(auction.verify_winner(winner, &proof).is_ok());

// Aggregate all commitments into one IVC fold
let fold = auction.fold_all(&mut rng).unwrap();
assert!(fold.unwrap().valid);
```

---

## Security parameters

| Level    | n  | q   | Security | Proof size |
| -------- | -- | --- | -------- | ---------- |
| NIST I   | 10 | 257 | 136 bits | 496 bytes  |
| NIST III | 16 | 257 | 232 bits | 784 bytes  |
| NIST V   | 22 | 257 | 328 bits | 1072 bytes |

Switch levels by changing the type parameter and params:

```rust
let mut auction = Auction::<257>::new(EgocParams::LEVEL3, &mut rng);
```

---

## How the bid encoding works

Each bid amount `a` is encoded into a message vector `m` of length `n`:

```
m[i] = (a + i) mod q   for i = 0..n
```

This spreads the bid across all message slots so the lift map `L(m, r)`
produces a full-rank matrix. The randomness vector `r` is sampled uniformly
from `[1, q-1]` (never zero) so that the hiding property holds.

The commitment `C = L(m, r) · g` hides the bid under the gauge element `g`.
Recovering `a` from `C` without `r` requires solving the Shadow Separation
Problem over SL(2, F257) — the hardness assumption underlying E-GOC.

---

## Limitations of this example

This is a demonstration, not a production auction system. Three simplifications
are present:

1. The auctioneer learns bid amounts when they are "revealed" in the demo.
   In a real system, amounts would be revealed only at auction close via a
   separate opening protocol.

2. The winner determination is based on the raw `amount` field stored in the
   `Bid` struct, not derived from the commitment itself. A full system would
   require a range proof or comparison protocol.

3. Bids from different bidders are not linked to real identities. An
   authentication layer (signatures, PKI) would be needed in production.

These simplifications are intentional — the goal is to show E-GOC's
cryptographic core without implementation complexity unrelated to the
commitment scheme itself.

---

## License

MIT OR Apache-2.0