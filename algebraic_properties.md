# Hat 4 — Algebraik Özellikler

Tarih: 2026-06-02  
Her madde için: Kanıtlandı / Test edildi / Açık soru

---

## 4.1 L Map'in Kernel ve İmajı

**L(m,r): Fq^n × Fq^n → Fq^{2n×2}**

### Kernel analizi

```
L(m,r) = 0_matris
  <=> her satır 0
  <=> [m[i], r[i]] = [0, 0]  AND  [r[i], -m[i]] = [0, 0]  (tüm i için)
  <=> m[i] = 0 AND r[i] = 0  (tüm i için)
  <=> (m, r) = (0,...,0, 0,...,0)
```

**ker(L) = {(0,...,0)} — trivial kernel**

### İnjectivity sonucu

L injective => C = L(m,r)·g = L(m',r')·g ile g invertible => L(m,r) = L(m',r') => m=m', r=r'

**Binding KOŞULSUZ — saf lineer cebir, SSP veya kriptografik varsayım gerektirmiyor.**

### İmaj boyutu

|Image(L)| = q^{2n} (her (m,r) çifti farklı bir matris üretiyor)

Commitment uzayı da q^{2n} — commit, Witness → CommitMatrix bir BİJEKSİYON.

| (q, n) | |Image(commit)| | log₂ |
|---|---|---|
| (257, 10) | 257^20 | 2^160 |
| (257, 16) | 257^32 | 2^256 |
| (257, 22) | 257^44 | 2^352 |

Çarpışma ihtimali: **sıfır** (bijection).  
Birthday saldırısı: anlamsız — her commitment'ın tek bir preimage'ı var.

**Durum: Kanıtlandı (Lemma 1 + algebraic argument)**

---

## 4.2 SL(2,Fq) Komütatör Yapısı

**Hesaplanan örnek (q=101):**
- g = [[2,1],[1,1]], h = [[3,1],[2,1]]
- [g,h] = g·h·g^{-1}·h^{-1} = [[9,90],[5,95]] ≠ I ✓ (non-abelian doğrulandı)

### Grup teorisi özellikleri

| Özellik | Değer |
|---|---|
| |SL(2,Fq)| | q(q-1)(q+1) = q^3 - q |
| q=257 için | 257·256·258 = 16,974,336 ≈ 2^24 |
| Merkez (Center) | {I, -I} — 2 eleman |
| PSL(2,Fq) = SL/Center | q>3 için simple group |
| Komütatör alt grubu | = SL(2,Fq) (perfect group, q>3) |

### Perfect group anlamı

"Perfect group" = kendi komütatör alt grubuna eşit.

Her g ∈ SL(2,Fq), komütatörlerin çarpımı olarak yazılabilir:
```
g = [a,b]·[c,d]·...  (commutator products)
```

### Keşif fırsatı (Phase 4.2 bağlantısı)

Komütatörler native challenge fonksiyonu olabilir:
- Challenge: e = [g, h] = g·h·g^{-1}·h^{-1} ∈ SL(2,Fq)
- Fq skaleri değil, grup elemanı
- Hash gerektirmiyor
- SSP'ye doğrudan algebraik bağlantı

Bu keşfedilmemiş alan — Phase 4.2 araştırmasının somut başlangıç noktası.

**Durum: Test edildi (q=101 ile), grup teorisi kanıtlandı, kriptografik kullanım açık soru**

---

## 4.3 Fold Birleşimlilik (Associativity)

**Test (q=101, n=4, seed=42):**
```
m1 = [51, 92, 14, 71], m2 = [60, 43, 78, 52], m3 = [42, 79, 12, 28]

(m1⊕m2)⊕m3 = [8, 58, 16, 3]
m1⊕(m2⊕m3) = [8, 58, 16, 3]
Eşit: True ✓
```

**Kanıt:**
```
Fq üzerinde toplama birleşimli:
(a + b) + c ≡ a + (b + c)  (mod q)
=> fold birleşimli
```

### Tree fold sırası bağımsızlığı

Bu özellik sayesinde:
- N witness'ı herhangi bir binary tree yapısıyla fold edilebilir
- Sonuç her zaman aynı: fold(w1,...,wN) = w1⊕...⊕wN
- Paralel fold uygulamaları doğru — her sıralama geçerli

### Fold gruboidü

Fold bir **abelian group action** — identity: zero witness (m=r=0).
```
fold(w, zero_witness) = w
fold(w1, w2) = fold(w2, w1)  (commutative)
fold(fold(w1,w2), w3) = fold(w1, fold(w2,w3))  (associative)
```

**Durum: Test edildi ve kanıtlandı**

---

## 4.4 Commitment Uzayının Boyutu

### Analitik hesap

commit: Witness → CommitMatrix tanımı:
1. L(m,r): injective (4.1'den)
2. ·g: injective (g invertible, det=1)
3. Kompozisyon: injective

```
|Image(commit)| = |Domain(commit)| = |Fq^n × Fq^n| = q^{2n}
```

Commitment matrisi uzayı: Fq^{2n×2} = q^{4n} eleman, ama bunun yalnızca q^{2n} tanesi geçerli commitment.

**Yoğunluk:** |Image| / |Space| = q^{2n} / q^{4n} = q^{-2n}

q=257, n=10 için: 257^{-20} ≈ 2^{-160} — uzayın çok küçük bir fraksiyonu gerçek commitment.

### Güvenlik çıkarımı

- Rastgele bir matris gerçek commitment değil: ihtimal 2^{-160}
- Forged commitment bulma: L(m,r)·g eşitliğini çözmeyi gerektirir — SSP problemi
- Binding için ek argüman: commitment uzayı "seyrek", ama her commitment'ın unique preimage'ı var

**Durum: Kanıtlandı (bijection argümanı)**

---

## 4.5 Bonus Keşif — Simetri Özellikleri

### Negasyon simetrisi
```
commit(m, r, g) = commit(-m, -r, -g)  [matris eşitliği]
```
Bu cross-gauge saldırısının algebraik temelidir. gauge_hash ile kapatılmış.

### Ölçekleme özelliği
```
commit(λm, λr, g) = λ·commit(m, r, g)  [linearity]
```
Scalar multiplication commitment'ı ölçekliyor. Bu IVC fold'un temel sebebi.

### Fold ile commit değişim özelliği (Commutativity ile commit)
```
commit(fold(w1,w2), g) = commit(w1,g) + commit(w2,g)
```
Kanıt: L(m1+m2, r1+r2)·g = L(m1,r1)·g + L(m2,r2)·g (linearity).

**Bu özellik IVC'nin matematiksel temelidir.**

---

## Özet

| Özellik | Durum | Açıklama |
|---|---|---|
| L injectivity | **Kanıtlandı** | ker(L) = {0} |
| commit bijection | **Kanıtlandı** | |Image| = q^{2n} |
| Unconditional binding | **Kanıtlandı** | L injective + g invertible |
| Non-abelian SL(2,Fq) | **Test edildi** | [g,h] ≠ I doğrulandı |
| Perfect group | **Kanıtlandı** | Grup teorisi (q>3) |
| Fold associativity | **Kanıtlandı** | Fq toplama birleşimli |
| Fold commutativity | **Kanıtlandı** | Fq toplama değişimeli |
| Commit + fold = fold + commit | **Kanıtlandı** | Linearity of L |
| Negasyon simetrisi | **Kanıtlandı** | Cross-gauge attack temel |
| Komütatör challenge | **Açık soru** | Phase 4.2 araştırması |
| Commitment uzay yoğunluğu | **Hesaplandı** | 2^{-160} (q=257, n=10) |