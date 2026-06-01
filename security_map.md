# Hat 3 — Güvenlik Sınır Haritası

Tarih: 2026-06-02  
Her özellik için: Koşulsuz / Hesapsal / ROM varsayımı / Açık soru

---

## 3.1 Binding

**Durum: KOŞULSUZbinding — tam algebraik, SSP varsayımı gerektirmiyor**

Kanıt zinciri (Theorem 1):
```
L(m,r)·g = L(m',r')·g
  [·g^{-1} her iki yandan]
L(m,r) = L(m',r')
  [L injectivity — Lemma 1]
m = m', r = r'
```

g^{-1} = [[d, -b], [-c, a]] mod q (det=1 olduğundan analitik form).

**Önem:** Bu binding'i quantum-resistant yapar. Grover veya Shor bu kanıtı kıramaz — saf lineer cebir.

**EasyCrypt durumu:** `binding_full_unconditional` — qed, 0 admits. Tam mekanik kanıt mevcut.

---

## 3.2 Hiding

**Durum: HESAPSAL — SSP varsayımı altında (Theorem 2)**

Adv^hide(A) ≤ q^{-(2n-3)}

İki adımlı kanıt:
1. Simetri argümanı: mesaj çiftleri swap edildiğinde commitment dağılımı aynı
2. SSP indirgeme: Pr[win] > 1/2 => SSP çözülebilir

**KAT vektörü r=0 durumu — KRİTİK BULGU:**

r=[0,...,0] ile hiding tamamen kırılıyor:
- C[2i] = [m[i]·g.a, m[i]·g.b] mod q
- g.a^{-1} mod q hesaplanabilir (g.a=81, g.a^{-1}=165 mod 257)
- m[i] = C[2i][0] · 165 mod 257 — doğrudan kurtarılabilir

Doğrulama: C[0][0]=81, 81·165 mod 257 = 1 = m[0] ✓ — mesaj geri alındı.

**Risk değerlendirmesi:**
- KAT testi için bilerek r=0: meşru test pattern
- Üretimde r=0 kullanımı: tam hiding ihlali
- Mevcut API: `Witness::new(m, r)` r=0 kabul ediyor, uyarı yok

**Öneri:** `Witness::new()` sıfır randomness için `debug_assert!` veya runtime uyarı eklenebilir. Ya da dokümantasyona "r uniform random seçilmeli" notu.

---

## 3.3 Cross-Gauge Saldırısı

**Durum: BLAKE3 çarpışma direnci altında KAPALI**

Saldırı mekanizması:
```
L(-m, -r)·(-g) = L(m, r)·g  [algebraik eşitlik, tam doğru]
```

Savunma: Commitment = (C_mat, H(g)) içeriyor. H(-g) ≠ H(g) ise saldırı başarısız.

**Kritik soru: g = -g mümkün mü?**
```
g = -g => 2g = 0 => g = 0 (q tek asal olduğundan)
Ama g ∈ SL(2,Fq) => det(g) = 1 => g ≠ 0
=> g ≠ -g her zaman
```

**Sonuç:** g ve -g her zaman farklı bit dizileri. H(g) = H(-g) ancak BLAKE3 çarpışması ile mümkün — mevcut güvenlik düzeyinde 2^128 iş gerektirir.

**EasyCrypt durumu:** `gauge_hash_neg_distinct` axiom olarak tanımlı — "empirically confirmed" notu var. Yukarıdaki kanıt bu axiom'u **theorem'e dönüştürebilir:**
- g ≠ -g (det kısıtından) + BLAKE3 çarpışma direnci (ROM axiom) → qed

Bu kanıt eksikliği ROADMAP'e araştırma maddesi olarak eklenebilir.

---

## 3.4 Küçük q Davranışı

| q | Güvenlik bit/adım | 128-bit için min n | Soundness hatası | Proof boyutu (min n) |
|---|---|---|---|---|
| 5  | 2 | 34 | 1/5 = %20 | 3184 B |
| 7  | 2 | 34 | 1/7 = %14 | 3184 B |
| 11 | 3 | 23 | 1/11 = %9 | 2224 B |
| 17 | 4 | 18 | 1/17 = %6 | 1744 B |
| 101| 6 | 13 | 1/101 = %1 | 1264 B |
| **257** | **8** | **10** | **1/257 = %0.4** | **496 B** |

**Sonuç:** q=257 optimal sweet spot.
- q<17: soundness hatası kabul edilemez (%6+)
- q=257: 8 bit/adım, n=10 ile 136 bit, 496 byte proof
- Küçük q değerleri `validate()` tarafından minimum güvenlik kontrolünden geçmiyor (n artırılmadıkça)

---

## 3.5 Proof Replay Saldırısı

**Durum: ROM varsayımı altında KAPALI**

Verifier kontrolü: `L(z_m,z_r)·g = A + e·C_mat`
Challenge: `e = BLAKE3(C_mat ‖ g ‖ A) mod (Q-1) + 1`

Replay senaryosu (farklı C_mat2 ile aynı proof):
```
e  = BLAKE3(C_mat  ‖ g ‖ A)
e2 = BLAKE3(C_mat2 ‖ g ‖ A) ≠ e  (BLAKE3 çoğunlukla)
Verifier: L(z_m,z_r)·g = A + e2·C_mat2  → başarısız
```

e2 = e olma ihtimali 1/(Q-1) = 1/256 ≈ %0.4 — tek deneme için kabul edilemez saldırı vektörü değil.

**Garanti:** Proof, oluşturulduğu C_mat'a kriptografik olarak bağlı.

---

## Özet Tablo

| Özellik | Güvenlik tipi | Varsayım | Durum |
|---|---|---|---|
| Binding | **Koşulsuz** | Yok | Kanıtlandı (EasyCrypt qed) |
| Hiding (r≠0) | Hesapsal | SSP | Kanıtlandı (EasyCrypt qed) |
| Hiding (r=0) | **YOK** | — | KRİTİK — API uyarısı gerekiyor |
| Cross-gauge | BLAKE3 çarpışma | ROM | Kapalı — axiom → theorem dönüşümü mümkün |
| Proof replay | ROM | ROM | Kapalı |
| Quantum (Grover) | Hesapsal | SSP | Binding: tam dayanıklı; Hiding: n×2 ile telafi |

---

## Açık Sorular

1. **r=0 API politikası:** Uyarı mı, reject mi, sadece dokümantasyon mu?
2. **gauge_hash_neg_distinct:** Axiom → theorem dönüşümü (det kısıtı + ROM) — araştırma maddesi
3. **QROM hiding:** `unruh_qrom` hâlâ axiom — Zhandry 2012 EasyCrypt entegrasyonu bekleniyor