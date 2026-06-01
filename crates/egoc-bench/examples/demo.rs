// E-GOC Demo Binary
// Run: cargo run --example demo -p egoc-bench

use egoc_commit::{commit, verify, Witness};
use egoc_field::{EgocParams, Fp};
use egoc_ivc::{ivc_fold, tree_fold};
use egoc_proof::{prove, verify_proof};
use egoc_sl2::random_sl2;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn line() {
    println!("{}", "─".repeat(62));
}
fn header(n: u8, title: &str) {
    println!();
    println!("{}", "═".repeat(62));
    println!("  §{}. {}", n, title);
    println!("{}", "═".repeat(62));
}

fn main() {
    println!("{}", "═".repeat(62));
    println!("  E-GOC — Group-Orbit Commitment Scheme");
    println!("  SL(2,Fq) native · SSP hardness · No trusted setup");
    println!("{}", "═".repeat(62));

    // ----------------------------------------------------------------
    // §1 — Security Parameters
    // ----------------------------------------------------------------
    header(1, "Security Parameters");

    let levels = [
        ("NIST Level I  ", EgocParams::LEVEL1),
        ("NIST Level III", EgocParams::LEVEL3),
        ("NIST Level V  ", EgocParams::LEVEL5),
    ];

    for (name, p) in &levels {
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
    // §2 — Commit / Verify
    // ----------------------------------------------------------------
    header(2, "Commit / Verify");

    let params = EgocParams::LEVEL1;
    let mut rng = StdRng::seed_from_u64(42);
    let g   = random_sl2(params.q, &mut rng);
    let w   = Witness::random_from_params(&params, &mut rng);
    let cmt = commit(&w, &g);

    println!("  Parameters: n={}, q={}", params.n, params.q);
    println!();
    println!("  Gauge g (SL2 matrix [[a,b],[c,d]]):");
    println!("    a={:3}  b={:3}  c={:3}  d={:3}  det=1",
        g.a.val(), g.b.val(), g.c.val(), g.d.val());
    println!();
    println!("  Commitment matrix C = L(m,r)·g  ({} rows × 2 cols):", cmt.matrix.rows().len());
    for (i, row) in cmt.matrix.rows().iter().enumerate() {
        println!("    C[{:2}] = [ {:3}, {:3} ]", i, row[0].val(), row[1].val());
    }
    println!();
    println!("  Gauge hash H(g) = BLAKE3(g.to_bytes()):");
    let gh = cmt.gauge_hash;
    println!("    {}", gh.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
    println!();
    println!("  Commitment total size: {} bytes  ({:.2} KB)", params.commit_bytes(), params.commit_bytes() as f64 / 1024.0);
    line();

    match verify(&w, &g, &cmt) {
        Ok(())  => println!("  verify(correct witness)  → Ok  ✓"),
        Err(e)  => println!("  verify FAILED: {}", e),
    }
    let w_bad = Witness::random_from_params(&params, &mut rng);
    match verify(&w_bad, &g, &cmt) {
        Ok(())  => println!("  verify(wrong witness)    → accepted  ✗  BUG"),
        Err(_)  => println!("  verify(wrong witness)    → rejected  ✓"),
    }

    // ----------------------------------------------------------------
    // §3 — NIZKP Prove / Verify
    // ----------------------------------------------------------------
    header(3, "NIZKP Prove / Verify  (Sigma + Fiat-Shamir + BLAKE3)");

    let pf = prove(&w, &g, &cmt.matrix, &mut rng);

    println!("  Proof π = (A, z_m, z_r):");
    println!();
    println!("  A = commitment to prover randomness  ({} rows × 2 cols):", pf.a_rows.len());
    for (i, row) in pf.a_rows.iter().enumerate() {
        println!("    A[{:2}] = [ {:3}, {:3} ]", i, row[0].val(), row[1].val());
    }
    println!();
    println!("  z_m (response for message, {} elements):", pf.z_m.len());
    println!("    [{}]", pf.z_m.iter().map(|f| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
    println!();
    println!("  z_r (response for randomness, {} elements):", pf.z_r.len());
    println!("    [{}]", pf.z_r.iter().map(|f| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
    println!();
    println!("  Proof byte layout:");
    println!("    header (n,q)  :  16 bytes");
    println!("    A rows        :  {} bytes  (2n × 2 × 8)", 32 * params.n);
    println!("    z_m           :  {} bytes  (n × 8)", 8 * params.n);
    println!("    z_r           :  {} bytes  (n × 8)", 8 * params.n);
    println!("    total         :  {} bytes  ({:.2} KB)", pf.byte_len(), pf.byte_len() as f64 / 1024.0);
    line();

    match verify_proof(&cmt.matrix, &g, &pf) {
        Ok(())  => println!("  verify_proof(correct proof)  → Ok  ✓"),
        Err(e)  => println!("  verify_proof FAILED: {}", e),
    }
    let pf_bad = prove(&w_bad, &g, &cmt.matrix, &mut rng);
    match verify_proof(&cmt.matrix, &g, &pf_bad) {
        Ok(())  => println!("  verify_proof(wrong proof)    → accepted  ✗  BUG"),
        Err(_)  => println!("  verify_proof(wrong proof)    → rejected  ✓"),
    }

    // Serialization round-trip
    let bytes = pf.to_bytes();
    let pf2   = egoc_proof::Proof::from_bytes(&bytes).expect("deserialize");
    match verify_proof(&cmt.matrix, &g, &pf2) {
        Ok(())  => println!("  serialize → deserialize → verify  → Ok  ✓"),
        Err(e)  => println!("  serialize round-trip FAILED: {}", e),
    }

    // ----------------------------------------------------------------
    // §4 — IVC Single Fold
    // ----------------------------------------------------------------
    header(4, "IVC Single Fold  (additive linearity over Fq)");

    let mut rng2 = StdRng::seed_from_u64(7);
    let g2 = random_sl2(params.q, &mut rng2);
    let w1 = Witness::random_from_params(&params, &mut rng2);
    let w2 = Witness::random_from_params(&params, &mut rng2);

    println!("  w1.m = [{}]", w1.m.iter().map(|f| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
    println!("  w2.m = [{}]", w2.m.iter().map(|f| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
    println!();

    match ivc_fold(&w1, &w2, &g2, &mut rng2) {
        Ok(fold) => {
            println!("  m_fold = m1+m2 mod q:");
            println!("    [{}]", fold.witness_fold.m.iter().map(|f| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
            println!();
            println!("  Fold validity:     {}", if fold.valid { "valid ✓" } else { "INVALID ✗" });
            println!("  Soundness error:   1/{} ≈ {:.6}", params.q, 1.0 / params.q as f64);
            println!("  Property checked:  L(m1+m2, r1+r2)·g = C1+C2  ✓");
        }
        Err(e) => println!("  ERROR: {}", e),
    }

    // ----------------------------------------------------------------
    // §5 — Tree Fold (N=8)
    // ----------------------------------------------------------------
    header(5, "Tree Fold  (N=8 witnesses, binary tree)");

    let mut rng3 = StdRng::seed_from_u64(99);
    let g3 = random_sl2(params.q, &mut rng3);
    let witnesses: Vec<Witness> = (0..8)
        .map(|_| Witness::random_from_params(&params, &mut rng3))
        .collect();

    println!("  N=8 witnesses, each n={}, q={}", params.n, params.q);
    println!("  Binary tree: {} fold operations across {} levels", 8 - 1, 3);
    println!();

    match tree_fold(witnesses, &g3, &mut rng3) {
        Ok(result) => {
            let (se_num, se_den) = result.soundness_err;
            println!("  Tree depth:        {}", result.depth);
            println!("  All steps valid:   {}", if result.all_valid { "yes ✓" } else { "NO ✗" });
            println!("  Soundness error:   {}/{} ≈ {:.6}  ({:.4}%)",
                se_num, se_den,
                se_num as f64 / se_den as f64,
                100.0 * se_num as f64 / se_den as f64);
            println!("  Final proof size:  {} bytes  ({:.2} KB)", result.final_proof.byte_len(), result.final_proof.byte_len() as f64 / 1024.0);
            println!("  Final commit rows: {} (= 2n)", result.final_commit.matrix.rows().len());
            println!();
            println!("  Final commit C[0] = [ {:3}, {:3} ]",
                result.final_commit.matrix.rows()[0][0].val(),
                result.final_commit.matrix.rows()[0][1].val());
            println!("  Final proof z_m   = [{}]",
                result.final_proof.z_m.iter().map(|f| format!("{:3}", f.val())).collect::<Vec<_>>().join(", "));
        }
        Err(e) => println!("  ERROR: {}", e),
    }

    // ----------------------------------------------------------------
    // §6 — Known Answer Test (KAT)
    // ----------------------------------------------------------------
    header(6, "Known Answer Test (KAT)  — deterministic test vector");

    let mut kat_rng = StdRng::seed_from_u64(0);
    let kat_g = random_sl2(params.q, &mut kat_rng);

    let kat_m: Vec<Fp> = (1..=params.n as u64)
        .map(|i| Fp::new(i, params.q))
        .collect();
    let kat_r: Vec<Fp> = vec![Fp::zero(params.q); params.n];

    println!("  Fixed seed:  StdRng::seed_from_u64(0)");
    println!("  m = [{}]", kat_m.iter().map(|f| format!("{}", f.val())).collect::<Vec<_>>().join(", "));
    println!("  r = [{}]", kat_r.iter().map(|f| format!("{}", f.val())).collect::<Vec<_>>().join(", "));
    println!("  q = {}", params.q);
    println!();
    println!("  g = [[{}, {}], [{}, {}]]  (det=1)",
        kat_g.a.val(), kat_g.b.val(), kat_g.c.val(), kat_g.d.val());
    println!();

    let kat_w   = Witness::new(kat_m, kat_r);
    let kat_cmt = commit(&kat_w, &kat_g);

    println!("  Commitment matrix C = L(m,r)·g:");
    for (i, row) in kat_cmt.matrix.rows().iter().enumerate() {
        println!("    C[{:2}] = [ {:3}, {:3} ]", i, row[0].val(), row[1].val());
    }
    println!();
    println!("  Gauge hash H(g):");
    println!("    {}", kat_cmt.gauge_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
    line();

    match verify(&kat_w, &kat_g, &kat_cmt) {
        Ok(())  => println!("  commit verify  → Ok  ✓"),
        Err(e)  => println!("  commit FAILED: {}", e),
    }

    let kat_pf = prove(&kat_w, &kat_g, &kat_cmt.matrix, &mut kat_rng);
    println!();
    println!("  Proof z_m = [{}]",
        kat_pf.z_m.iter().map(|f| format!("{}", f.val())).collect::<Vec<_>>().join(", "));
    println!("  Proof z_r = [{}]",
        kat_pf.z_r.iter().map(|f| format!("{}", f.val())).collect::<Vec<_>>().join(", "));
    println!();

    match verify_proof(&kat_cmt.matrix, &kat_g, &kat_pf) {
        Ok(())  => println!("  proof verify   → Ok  ✓"),
        Err(e)  => println!("  proof FAILED:  {}", e),
    }

    println!();
    println!("{}", "═".repeat(62));
    println!("  All sections complete.");
    println!("{}", "═".repeat(62));
    println!();
    println!("  Run benchmarks:  cargo bench -p egoc-bench");
    println!("  Run tests:       cargo test --workspace");
}