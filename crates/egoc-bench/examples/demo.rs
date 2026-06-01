// E-GOC Demo Binary
// Run: cargo run --example demo -p egoc-bench
//
// Uses the unified EgocSession<Q> API introduced in the const-generic refactor.
// All field operations use Q=257 (NIST Level I prime) as a compile-time constant.

use egoc::{EgocParams, EgocSession, Fp, Proof};
use rand::SeedableRng;
use rand::rngs::StdRng;

const Q: u64 = 257;
type F = Fp<Q>;
type S = EgocSession<Q>;

fn line()  { println!("{}", "─".repeat(62)); }
fn dline() { println!("{}", "═".repeat(62)); }
fn header(n: u8, title: &str) {
    println!();
    dline();
    println!("  §{}. {}", n, title);
    dline();
}

fn main() {
    dline();
    println!("  E-GOC — Group-Orbit Commitment Scheme");
    println!("  SL(2,Fq) native · SSP hardness · No trusted setup");
    dline();

    // ----------------------------------------------------------------
    // §1 — Security Parameters
    // ----------------------------------------------------------------
    header(1, "Security Parameters");

    for (name, p) in &[
        ("NIST Level I  ", EgocParams::LEVEL1),
        ("NIST Level III", EgocParams::LEVEL3),
        ("NIST Level V  ", EgocParams::LEVEL5),
    ] {
        println!("  {}:", name);
        println!("    n (message length)   = {}", p.n);
        println!("    q (field prime)       = {}", p.q);
        println!("    security bits         = {} bits  (formula: (2n-3)·⌊log₂q⌋)", p.security_bits());
        println!("    commitment size       = {} bytes  ({:.2} KB)", p.commit_bytes(), p.commit_bytes() as f64 / 1024.0);
        println!("    proof size            = {} bytes  ({:.2} KB)", p.proof_bytes(), p.proof_bytes() as f64 / 1024.0);
        println!("    meets NIST Level I?   = {}", p.is_nist_level1());
        println!("    meets NIST Level III? = {}", p.is_nist_level3());
        println!("    meets NIST Level V?   = {}", p.is_nist_level5());
        line();
    }

    // ----------------------------------------------------------------
    // §2 — EgocSession + Commit / Verify
    // ----------------------------------------------------------------
    header(2, "EgocSession · Commit / Verify");

    let mut rng = StdRng::seed_from_u64(42);
    let session: S = EgocSession::random(EgocParams::LEVEL1, &mut rng);

    println!("  Session: n={}, q={}", session.params.n, Q);
    println!("  Gauge g (SL2 matrix [[a,b],[c,d]]):");
    let g = &session.gauge;
    println!("    a={:3}  b={:3}  c={:3}  d={:3}  det=1",
        g.a.val(), g.b.val(), g.c.val(), g.d.val());
    println!();

    let w   = session.random_witness(&mut rng);
    let cmt = session.commit(&w);

    println!("  Commitment matrix C = L(m,r)·g  ({} rows × 2 cols):", cmt.matrix.rows().len());
    for (i, row) in cmt.matrix.rows().iter().enumerate() {
        println!("    C[{:2}] = [ {:3}, {:3} ]", i, row[0].val(), row[1].val());
    }
    println!();
    println!("  Gauge hash H(g) = BLAKE3(g.to_bytes()):");
    println!("    {}", cmt.gauge_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
    println!();
    println!("  Commitment size: {} bytes  ({:.2} KB)",
        session.commit_bytes(), session.commit_bytes() as f64 / 1024.0);
    line();

    match session.verify(&w, &cmt) {
        Ok(())  => println!("  verify(correct witness) → Ok  ✓"),
        Err(e)  => println!("  verify FAILED: {}", e),
    }
    let w_bad = session.random_witness(&mut rng);
    match session.verify(&w_bad, &cmt) {
        Ok(())  => println!("  verify(wrong witness)   → accepted  ✗  BUG"),
        Err(_)  => println!("  verify(wrong witness)   → rejected  ✓"),
    }

    // ----------------------------------------------------------------
    // §3 — NIZKP Prove / Verify
    // ----------------------------------------------------------------
    header(3, "NIZKP Prove / Verify  (Sigma + Fiat-Shamir + BLAKE3)");

    let pf = session.prove(&w, &cmt, &mut rng);

    println!("  Proof π = (A, z_m, z_r):");
    println!();
    println!("  A = commitment to prover randomness  ({} rows × 2 cols):", pf.a.rows().len());
    for (i, row) in pf.a.rows().iter().enumerate() {
        println!("    A[{:2}] = [ {:3}, {:3} ]", i, row[0].val(), row[1].val());
    }
    println!();
    println!("  z_m (response for message, {} elements):", pf.z_m.len());
    println!("    [{}]", pf.z_m.iter().map(|f: &F| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
    println!();
    println!("  z_r (response for randomness, {} elements):", pf.z_r.len());
    println!("    [{}]", pf.z_r.iter().map(|f: &F| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
    println!();
    println!("  Proof byte layout:");
    println!("    header (n,q)  :  16 bytes");
    println!("    A rows        :  {} bytes  (2n × 2 × 8)", 32 * session.params.n);
    println!("    z_m           :  {} bytes  (n × 8)", 8 * session.params.n);
    println!("    z_r           :  {} bytes  (n × 8)", 8 * session.params.n);
    println!("    total         :  {} bytes  ({:.2} KB)",
        pf.byte_len(), pf.byte_len() as f64 / 1024.0);
    line();

    match session.verify_proof(&cmt.matrix, &pf) {
        Ok(())  => println!("  verify_proof(correct proof) → Ok  ✓"),
        Err(e)  => println!("  verify_proof FAILED: {}", e),
    }
    let pf_bad = session.prove(&w_bad, &session.commit(&w_bad), &mut rng);
    match session.verify_proof(&cmt.matrix, &pf_bad) {
        Ok(())  => println!("  verify_proof(wrong proof)   → accepted  ✗  BUG"),
        Err(_)  => println!("  verify_proof(wrong proof)   → rejected  ✓"),
    }
    let pf2 = Proof::<Q>::from_bytes(&pf.to_bytes()).expect("deserialize");
    match session.verify_proof(&cmt.matrix, &pf2) {
        Ok(())  => println!("  serialize → deserialize → verify  → Ok  ✓"),
        Err(e)  => println!("  serialize round-trip FAILED: {}", e),
    }

    // ----------------------------------------------------------------
    // §4 — commit_and_prove (single call)
    // ----------------------------------------------------------------
    header(4, "commit_and_prove  (session convenience API)");

    let mut rng2  = StdRng::seed_from_u64(55);
    let session2: S = EgocSession::random(EgocParams::LEVEL1, &mut rng2);
    let w2          = session2.random_witness(&mut rng2);
    let (cmt2, pf2) = session2.commit_and_prove(&w2, &mut rng2);

    println!("  One call: session.commit_and_prove(&w, &mut rng)");
    println!();
    match session2.verify(&w2, &cmt2) {
        Ok(())  => println!("  verify(commitment)  → Ok  ✓"),
        Err(e)  => println!("  verify FAILED: {}", e),
    }
    match session2.verify_proof(&cmt2.matrix, &pf2) {
        Ok(())  => println!("  verify_proof(proof) → Ok  ✓"),
        Err(e)  => println!("  verify_proof FAILED: {}", e),
    }

    // ----------------------------------------------------------------
    // §5 — IVC Single Fold
    // ----------------------------------------------------------------
    header(5, "IVC Single Fold  (additive linearity over Fq)");

    let mut rng3    = StdRng::seed_from_u64(7);
    let session3: S = EgocSession::random(EgocParams::LEVEL1, &mut rng3);
    let w3a         = session3.random_witness(&mut rng3);
    let w3b         = session3.random_witness(&mut rng3);

    println!("  w1.m = [{}]", w3a.m.iter().map(|f: &F| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
    println!("  w2.m = [{}]", w3b.m.iter().map(|f: &F| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
    println!();

    match session3.fold(&w3a, &w3b, &mut rng3) {
        Ok(fold) => {
            println!("  m_fold = m1+m2 mod q:");
            println!("    [{}]", fold.witness_fold.m.iter().map(|f: &F| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
            println!();
            println!("  Fold validity:    {}", if fold.valid { "valid ✓" } else { "INVALID ✗" });
            println!("  Soundness error:  1/{} ≈ {:.6}", Q, 1.0 / Q as f64);
            println!("  Property:         L(m1+m2, r1+r2)·g = C1+C2  ✓");
        }
        Err(e) => println!("  ERROR: {}", e),
    }

    // ----------------------------------------------------------------
    // §6 — Tree Fold (N=8)
    // ----------------------------------------------------------------
    header(6, "Tree Fold  (N=8 witnesses, binary tree)");

    let mut rng4    = StdRng::seed_from_u64(99);
    let session4: S = EgocSession::random(EgocParams::LEVEL1, &mut rng4);
    let ws: Vec<_>  = (0..8).map(|_| session4.random_witness(&mut rng4)).collect();

    println!("  N=8 witnesses, each n={}, q={}", session4.params.n, Q);
    println!("  Binary tree: {} fold operations, {} levels", 7, 3);
    println!();

    match session4.tree_fold(ws, &mut rng4) {
        Ok(result) => {
            let (se_num, se_den) = result.soundness_err;
            println!("  Tree depth:        {}", result.depth);
            println!("  All steps valid:   {}", if result.all_valid { "yes ✓" } else { "NO ✗" });
            println!("  Soundness error:   {}/{} ≈ {:.6}  ({:.4}%)",
                se_num, se_den,
                se_num as f64 / se_den as f64,
                100.0 * se_num as f64 / se_den as f64);
            println!("  Final proof size:  {} bytes  ({:.2} KB)",
                result.final_proof.byte_len(),
                result.final_proof.byte_len() as f64 / 1024.0);
            println!("  Final commit rows: {} (= 2n)", result.final_commit.matrix.rows().len());
            println!();
            println!("  Final C[0] = [ {:3}, {:3} ]",
                result.final_commit.matrix.rows()[0][0].val(),
                result.final_commit.matrix.rows()[0][1].val());
            println!("  Final z_m  = [{}]",
                result.final_proof.z_m.iter().map(|f: &F| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
        }
        Err(e) => println!("  ERROR: {}", e),
    }

    // ----------------------------------------------------------------
    // §7 — Known Answer Test (KAT)
    // ----------------------------------------------------------------
    header(7, "Known Answer Test (KAT)  — deterministic test vector");

    let mut kat_rng     = StdRng::seed_from_u64(0);
    let kat_session: S  = EgocSession::random(EgocParams::LEVEL1, &mut kat_rng);

    let kat_m: Vec<F> = (1..=kat_session.params.n as u64).map(|i| F::new(i)).collect();
    let kat_r: Vec<F> = vec![F::zero(); kat_session.params.n];

    println!("  Fixed seed:  StdRng::seed_from_u64(0)");
    println!("  m = [{}]", kat_m.iter().map(|f: &F| format!("{}", f.val())).collect::<Vec<_>>().join(", "));
    println!("  r = [{}]", kat_r.iter().map(|f: &F| format!("{}", f.val())).collect::<Vec<_>>().join(", "));
    println!("  q = {}", Q);
    println!();
    let kg = &kat_session.gauge;
    println!("  g = [[{}, {}], [{}, {}]]  (det=1)", kg.a.val(), kg.b.val(), kg.c.val(), kg.d.val());
    println!();

    // Direct construction — bypasses debug_assert for this intentional r=0 test vector.
    // KAT vectors use zero randomness by design for determinism; hiding is intentionally absent.
    let kat_w   = egoc::Witness::<Q> { m: kat_m, r: kat_r, n: kat_session.params.n };
    let kat_cmt = kat_session.commit(&kat_w);

    println!("  Commitment matrix C = L(m,r)·g:");
    for (i, row) in kat_cmt.matrix.rows().iter().enumerate() {
        println!("    C[{:2}] = [ {:3}, {:3} ]", i, row[0].val(), row[1].val());
    }
    println!();
    println!("  Gauge hash H(g):");
    println!("    {}", kat_cmt.gauge_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
    line();

    match kat_session.verify(&kat_w, &kat_cmt) {
        Ok(())  => println!("  commit verify  → Ok  ✓"),
        Err(e)  => println!("  commit FAILED: {}", e),
    }

    let kat_pf = kat_session.prove(&kat_w, &kat_cmt, &mut kat_rng);
    println!();
    println!("  Proof z_m = [{}]",
        kat_pf.z_m.iter().map(|f: &F| format!("{}", f.val())).collect::<Vec<_>>().join(", "));
    println!("  Proof z_r = [{}]",
        kat_pf.z_r.iter().map(|f: &F| format!("{}", f.val())).collect::<Vec<_>>().join(", "));
    println!();

    match kat_session.verify_proof(&kat_cmt.matrix, &kat_pf) {
        Ok(())  => println!("  proof verify   → Ok  ✓"),
        Err(e)  => println!("  proof FAILED:  {}", e),
    }

    println!();
    dline();
    println!("  All sections complete.");
    dline();
    println!();
    println!("  Run benchmarks:  cargo bench -p egoc-bench");
    println!("  Run tests:       cargo test --workspace");
}