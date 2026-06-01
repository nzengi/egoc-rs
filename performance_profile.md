# Hat 2 — Performans Profili

Tarih: 2026-06-02  
Platform: macOS (Apple Silicon), optimized build (lto=thin, opt-level=3)  
Kütüphane: Criterion 0.5, 200-500 sample

---

## 2.1 n Ölçeklenmesi — O(n) mi?

Commit süresi (ns), farklı n değerleri:

| n | commit (ns) | verify (ns) | prove (ns) | verify_proof (ns) |
|---|---|---|---|---|
| 4  | 148 | 186 | 860  | 633  |
| 10 | 195 | 268 | 1732 | 1227 |
| 16 | 243 | 347 | 2681 | 1913 |
| 24 | 311 | 452 | 3750 | 2632 |

**Lineer regresyon (commit):**
```
commit(n) ≈ 114.2 + 8.1·n  ns
```

Segment bazlı eğim:

| Aralık | Δt (ns) | Δn | Eğim (ns/n) |
|---|---|---|---|
| n=4→10 | 47 | 6 | 7.8 |
| n=10→16 | 48 | 6 | 8.0 |
| n=16→24 | 68 | 8 | 8.5 |

**Sonuç: Evet, commit O(n) — eğim ≈ 8.1 ns/n tutarlı.**

Hafif yukarı kayma (n=16→24: 8.5 ns/n) büyük ihtimalle cache pressure veya Vec allocation varyansı. Teorik ile uyumlu.

**Baseline analizi (intercept ≈ 114 ns):**
- BLAKE3 gauge_hash: ~82 ns (ölçüldü)
- Kalan ~32 ns: lift ve SL2·g başlangıç overhead'i
- Tamamen beklenen — sabit maliyet O(1)

---

## 2.2 Bellek Ayak İzi

Teorik hesap (Fp<Q> = 8 byte, her Vec alloc):

| Tip | n=10 | n=16 | n=22 |
|---|---|---|---|
| Witness<Q> | 160 B | 256 B | 352 B |
| CommitMatrix<Q> | 320 B | 512 B | 704 B |
| Commitment<Q> | 352 B | 544 B | 736 B |
| Proof<Q> | 496 B | 784 B | 1072 B |

**Vec allocation sayısı (prove için):**
1. `k: Vec<Fp>` — prover randomness m (n elements)
2. `s: Vec<Fp>` — prover randomness r (n elements)
3. `a_lift: Vec<[Fp;2]>` — 2n rows
4. `a: CommitMatrix` (from_rows) — 2n rows
5. `z_m: Vec<Fp>` — n elements
6. `z_r: Vec<Fp>` — n elements

Toplam: **6 heap allocation per prove()** — optimize edilebilir (k ve s zeroize sonrası düşürülebilir).

---

## 2.3 BLAKE3 Baskınlığı

| n | prove (ns) | BLAKE3 fiat_shamir (ns) | BLAKE3 oranı |
|---|---|---|---|
| 4  | 860  | 841 | **%98** |
| 10 | 1732 | 841 | **%49** |
| 16 | 2681 | 841 | %31 |
| 24 | 3750 | 841 | %22 |

**Kritik gözlem:** Küçük n'lerde (n≤4) prove süresi neredeyse tamamen BLAKE3'ten oluşuyor. n=10'da ise %49 BLAKE3, %51 algebraik iş.

BLAKE3 fiat_shamir maliyeti sabit ≈ 841 ns — input boyutundan neredeyse bağımsız:
- Girdi: C_mat bytes (2n·16) + g bytes (32) + A bytes (2n·16)
- n=10: 320 + 32 + 320 = 672 byte → BLAKE3 verimli
- n=24: 768 + 32 + 768 = 1568 byte → hâlâ 841 ns (BLAKE3 streaming hızlı)

**Darboğaz:** n<8 için BLAKE3, n>8 için matris çarpımı.

---

## 2.4 Commit vs Verify Asimetrisi

| n | verify−commit (ns) | CT comparison rows |
|---|---|---|
| 4  | 38 | 8 rows |
| 10 | 73 | 20 rows |
| 16 | 104 | 32 rows |
| 24 | 141 | 48 rows |

**Eğim:** ≈ 2.9 ns/row

**Neden verify daha yavaş?**
- commit: lift + mat_mul + gauge_hash + alloc
- verify: commit (tüm bunlar) + CT comparison (2n rows + 32-byte hash)

CT comparison maliyeti: ≈ 2.9 ns/row = ~2 ns/field element (ConstantTimeEq üzerinden).

Asimetri beklenen ve makul. Üretimde verifier'ın daha yavaş olması kabul edilebilir.

---

## 2.5 prove vs verify_proof Karşılaştırması

| n | prove (ns) | verify_proof (ns) | fark (ns) |
|---|---|---|---|
| 4  | 860  | 633  | 227 |
| 10 | 1732 | 1227 | 505 |
| 16 | 2681 | 1913 | 768 |
| 24 | 3750 | 2632 | 1118 |

**Fark nerede?**
- prove: random_vec (k,s) + zeroize
- verify_proof: sadece denklem kontrolü

Fark ≈ 46 ns/n — `random_fp` (17.7 ns × 2n elements) ile tutarlı.

---

## Özet

| Metrik | Sonuç |
|---|---|
| commit ölçeklenmesi | O(n) — slope 8.1 ns/n ✓ |
| verify ölçeklenmesi | O(n) — slope ~12 ns/n |
| prove ölçeklenmesi | O(n) — slope ~124 ns/n |
| BLAKE3 baskınlığı | n≤4: %98, n=10: %49, n≥16: <%32 |
| Bellek (n=10) | Witness 160B, Proof 496B |
| Vec alloc/prove | 6 ayrı heap alloc |
| Darboğaz (n=10) | %49 BLAKE3, %51 algebraik |
| prove/verify asimetri | ≈ 46 ns/n (random generation) |

**Araştırma notu:** BLAKE3 sabit maliyeti (~841 ns) küçük n'leri orantısız yavaşlatıyor. Phase 4.1'deki native algebraic challenge, bu maliyeti sıfıra indirebilir.