# VeRedact-PQ — Complete Protocol Flow (Revised)

**Core principle.** ทุก data owner แก้ไข/ลบเฉพาะเนื้อหาของตนเองได้ แต่ไม่มีใครแก้ `{org, type, opened}` ซึ่งเป็น provenance ของ record ได้เลย ขอบเขตนี้ถูก commit ไว้ก่อนที่ record ใดจะเกิดขึ้น และถูกบังคับด้วย cryptography ที่สามจุดแยกกัน

**เอาออกจากเวอร์ชันก่อน:** endorser committee (ℰ), VRF sortition, randomness beacon (bcn_R). อำนาจอนุมัติมาจาก proof + threshold attestation ของ node ไม่ใช่จากการโหวตของคน

**Entities**

| สัญลักษณ์ | บทบาท |
|---|---|
| 𝒪 | Data owner / organization ที่ submit record |
| 𝒮 | Data subject — เจ้าของข้อมูลส่วนบุคคล ผู้ร้องขอ redaction |
| 𝒩 | Nodes — ถือ trapdoor share, รัน MPC, ออก attestation |
| 𝒟 | Off-chain store |
| 𝒜 | Auditor |

**Running example.** ธนาคาร A บันทึก KYC ของสมชายเมื่อ 2014-03-14 ระยะเก็บรักษาตามกฎหมาย 10 ปี ปัจจุบัน 2026-08 → พ้นระยะแล้ว สมชายขอใช้สิทธิ์ลบข้อมูลส่วนบุคคลของตน แต่ **ต้องไม่สามารถลบร่องรอยว่า "ธนาคาร A เคยเปิดบัญชี KYC เมื่อ 2014-03-14"** ได้ เพราะนั่นคือหลักฐานที่ regulator ต้องใช้

Parameter ที่ใช้ตลอดตัวอย่าง: `n = 12` nodes, `t = 4`, `S = 6` shards, `S_H = 2`, `S_M = 4`, `S_L = 6`, `t_mpc[L] = 6`, `t_mpc[M] = 7`, `t_mpc[H] = 9`

---

## Phase I — System Initialization

### Step 1: Entity Registration

enroll 𝒪, 𝒮, 𝒩 ผ่าน MSP โดย node ลงทะเบียนเพียง X.509 identity

```
𝒩 = { N₁, …, N₁₂ },   cert(Nᵢ) ← MSP
```

ไม่มี VRF keypair และไม่มี endorser role อีกต่อไป — node ไม่ต้องพิสูจน์ว่า "ถูกสุ่มเลือก" เพราะไม่มีการสุ่มเลือกแล้ว

### Step 2: Distributed Trapdoor Generation

กำหนด `Ā ← R_q^{n×m̄}` จาก public seed `sd` node `Nᵢ` สุ่ม `Rᵢ ← 𝒟_σ^{m̄×k}` แล้วประกาศ

```
A_pub,i = − Ā · Rᵢ  (mod q)

A_pub = Σᵢ₌₁ⁿ A_pub,i = − Ā · R,   R = Σᵢ Rᵢ

A = [ Ā ‖ A_pub + G ] ∈ R_q^{n×m},   m = m̄ + k
```

`R` ไม่เคยถูกประกอบขึ้นที่ใดเลย เพราะการ map จาก `Rᵢ → A_pub,i` เป็น linear จึงรวมผลได้โดยไม่ต้องทำ interactive MPC ตอน setup

### Step 3: Share Validity Proof

```
πᵢ : PoK{ Rᵢ : A_pub,i = − Ā Rᵢ  ∧  ‖Rᵢ‖ ≤ B }
```

share ที่ norm เกินเพียงตัวเดียวจะทำให้ aggregate trapdoor ใช้งานไม่ได้แบบเงียบ ๆ การใช้ exact proof แทน relaxed proof หลีกเลี่ยงการต้องขยาย `σ, β` แบบถาวร

### Step 4: Transparent Parameter Publication

ประกาศ circuit commitment ต่อ tier และ deploy `Verifier_T`, `T ∈ {H, M, L}` — ไม่มี trusted setup, ไม่มี pairing-based key หนึ่ง verifier ต่อหนึ่ง tier เพราะ shard ไม่เปลี่ยน circuit

### Step 5: Policy Registration — ขอบเขตความเป็นเจ้าของ

นี่คือจุดที่ concept "แก้ได้แค่ของตัวเอง" ถูกตรึงไว้

```
PolicyRegistry[KYC]     : 𝔽 = {org, type, opened}   𝔼 = {name, natid, addr}
PolicyRegistry[LOAN]    : 𝔽 = {org, type, opened}   𝔼 = {borrower, terms}
PolicyRegistry[LOG]     : 𝔽 = {org, type, seq}      𝔼 = {payload}
PolicyRegistry[COMMENT] : 𝔽 = {timestamp}           𝔼 = everything else
```

พร้อม threshold

```
ζ₁ = 0.35 < ζ₂ = 0.65
t ≤ t_mpc[L] < t_mpc[M] < t_mpc[H] ≤ n
```

ทุก `𝔽` มี provenance อยู่ การลงทะเบียนก่อนที่ record ใด ๆ จะเกิดขึ้น คือเหตุผลที่ขอบเขตนี้ต่อรองไม่ได้ — ไม่มีใครแก้ policy ได้เมื่อมี record ใด record หนึ่งเป็นเดิมพันอยู่แล้ว

### Step 6: Offline Preprocessing Pool

```
𝒫ⱼ = ( [[p]], [[w]], edaBits, Beaver triples ),   w = A·p
```

MAC-authenticated จำกัดการสุ่มแบบ non-linear ไว้ในขั้นที่ไม่ขึ้นกับคำขอ

### Step 7: Partition and Index Initialization

```
SubjectRegistry     = SMT over H(subjID ‖ salt)     → publish acc_root
NullifierAcc        = SMT, S subtrees by shard      → one global root
LegalHoldRegistry   = SMT over held record_ids      → hold_root
InvestigationFlags  = SMT over flagged record_ids
PendingIndex[s]     = { record_id → pending_req }   ← per shard, tier-agnostic
BatchPool[T][s]     = ∅
TimeIndex[e]        = ( R_first, R_last, AccRoot )
```

**Output**

```
𝓘_init = { sd, H(A_pub), Θ, e, acc_root, hold_root }
```

> **ตัวอย่าง.** ธนาคาร A enroll เป็น 𝒪, สมชาย enroll เป็น 𝒮 ได้ leaf `H(subjID_somchai ‖ salt)` ใน SubjectRegistry, node ทั้ง 12 ตัวประกาศ `A_pub,i` พร้อม `πᵢ` และ policy ของ type `KYC` ถูกลงทะเบียนว่า `org, type, opened` แตะไม่ได้ ตั้งแต่ก่อนที่บัญชีของสมชายจะถูกเปิด

---

## Phase II — Data Submission and Commitment

### Step 1: Partition by Registered Policy

แยก `m` ตาม `PolicyRegistry[type]` **ไม่ใช่ตามที่ผู้ส่งเลือกเอง**

```
m^F = m|_𝔽 ,   m^E = m|_𝔼

c^F = H( m^F ‖ s^F )      ← provenance, ถาวร
c^E = H( m^E ‖ s^E )      ← เนื้อหาของเจ้าของ, ลบได้
ℓ   = H( c^F ‖ c^E )
```

ต้อง salt ทั้งคู่ — commitment ต่อเลขบัตรประชาชนที่ไม่ salt (entropy ~30 bit) สามารถกู้คืนด้วย exhaustive search จากประวัติ ledger ได้

### Step 2: Crypto-Shredding Setup

```
k ← {0,1}^λ ,   ct = m^E ⊕ PRG(k)   เก็บที่ 𝒟
```

plaintext ไม่เคยขึ้น chain การเลือก handle `s^E` ตรงนี้คือสิ่งที่ทำให้การลบใน Phase V เหลือแค่การลบค่าเดียว

### Step 3: Metadata Declaration

```
ℳⱼ = ( type, ret_ℳ, scope, 𝒪ⱼ, opened )   commit อยู่ภายใน m^F
```

จงใจวางไว้ในส่วนที่แก้ไม่ได้ เพราะ `type` เป็นทั้งตัวเลือก policy และเป็น input ของ `φ^typ` ในคะแนน sensitivity หากอยู่ในส่วนที่แก้ได้ ผู้ร้องขอจะ relabel `KYC → COMMENT` เพื่อให้ได้ทั้งขอบเขตแก้ไขที่หลวมกว่าและ threshold ที่ต่ำกว่าพร้อมกัน

### Step 4: Merkle Batching

```
ρ = MT.Root( ℓ₁, …, ℓ_Nℓ )
```

หนึ่ง chameleon operation ต่อหนึ่ง tree ไม่ใช่ต่อหนึ่ง record

### Step 5: Ownership Binding

```
record_id ∈ owned( subjID )   บันทึกใน SubjectRegistry
```

เพื่อให้ proof ในอนาคตยืนยันความเป็นเจ้าของได้โดยไม่เปิดเผยตัวตน

### Step 6: Tagging

```
uⱼ = H( bid ‖ j ‖ νⱼ )
```

client เป็นผู้สร้าง เพราะ tag เป็น input ของ commitment ที่คำนวณก่อนที่ ordering จะกำหนด txID ความไม่ซ้ำรับประกันด้วย on-chain registry

### Step 7: PQ Chameleon Commitment

```
c = A·r + H_q( u ‖ ρ )   (mod q)

admissible  ⟺  ‖r‖₂ ≤ β
```

norm bound คือที่มาของความยาก — ถ้าไม่มี ระบบจะ underdetermined และแก้ได้ด้วย linear algebra ธรรมดา

**Output**

```
𝓢_ℬ = ( u, c, ρ, {c^F}, {ℳ}, H(r), e )
𝒟 เก็บ: ct, s^F, s^E, k, r, sibling paths
```

> **ตัวอย่าง.** record `rec_8842`
> ```
> m^F = { org: BankA, type: KYC, opened: 2014-03-14 }
> m^E = { name: "สมชาย พ.", natid: 1-1013-•••••-••-•, addr: "…ปทุมธานี" }
> c^F = H(m^F ‖ s^F) = 0x7a3f…    c^E = H(m^E ‖ s^E) = 0xc21b…
> ℓ   = H(c^F ‖ c^E) = 0x9e44…
> ℳ  = ( KYC, ret_ℳ = 10y, scope = cross-org, BankA, 2014-03-14 )
> ```
> `ℓ` ถูกรวมกับอีก 9,999 leaves เป็น `ρ` แล้ว commit เป็น `c = A·r + H_q(u ‖ ρ)` ขึ้น chain สิ่งที่อยู่บน chain คือ `c` และ `c^F` — ตัว `m^E` อยู่ที่ 𝒟 ในรูป `ct` เท่านั้น

---

## Phase III — Request, Lawfulness, and Two-Dimensional Partitioning

### Step 1: Request Submission

```
Req = ⟨ π_P, pub_signals, τ, s, timestamp ⟩
```

ไม่มี external signature — signature เปิดเผย `pk` และทำให้ระบุตัวผู้ร้องขอได้ ทั้งที่ไม่ได้พิสูจน์อะไรเกินจาก ZKP

### Step 2: Ownership and Lawfulness Proof — จุดบังคับขอบเขตจุดแรก

```
π_P : PoK{ ( subjID, salt, path, sk, m′, s′^E ) :

    MT.Vf( H(subjID ‖ salt), path, acc_root ) = 1      ① เป็นเจ้าของที่ลงทะเบียนไว้
  ∧ pk = KeyGen(sk)  bound to leaf                     ② ถือกุญแจจริง
  ∧ record_id ∈ owned(subjID)                          ③ เป็นเจ้าของ record นี้
  ∧ policy_id = PolicyOf( ℳ.type )                     ④ policy ตรงกับ type
  ∧ WellFormed( Commit(m′), policy_id )                ⑤ แตะเฉพาะ field ใน 𝔼
  ∧ ¬ LegalHold( record_id, hold_root )                ⑥ ไม่ติด legal hold
  ∧ RetentionExpired( ℳ.ret_ℳ, ℳ.opened, now )         ⑦ พ้นระยะเก็บรักษา
  ∧ nullifier = H( sk, record_id, version )            ⑧ กัน replay
  ∧ old_hash = CurrentState( record_id ) }             ⑨ ไม่ stale
```

โดย conjunct ⑤ ขยายเป็น

```
WellFormed(m′, policy_id) ≡
      c^F′ = c^F                          ← ไบต์ต่อไบต์ ห้ามเปลี่ยน
    ∧ modified(m′) ⊆ 𝔼(policy_id)
    ∧ ℓ′ = H( c^F ‖ c^E′ ),  c^E′ = H(m′^E ‖ s′^E)
```

**เหตุผลที่ต้องมีทั้ง ③ และ ④–⑤:** ถ้าไม่มี ③ ลูกค้าที่ลงทะเบียนคนใดก็ได้แก้ record ของคนอื่นได้ ถ้าไม่มี ④ ผู้ร้องขออ้าง policy ที่หลวมกว่าซึ่งเป็นของ type อื่นได้ สองข้อนี้จำกัดคนละแกน — ③ จำกัดว่า *ของใคร* ส่วน ④–⑤ จำกัดว่า *ฟิลด์ไหน*

conjunct ⑥–⑦ คือสิ่งที่เข้ามาแทนดุลยพินิจของ DPO/committee เดิม governance กลายเป็น algorithmic ซึ่งเป็น design ที่ป้องกันได้ (uniform และ auditable) แต่เป็น claim คนละแบบ จึงต้องเขียนโต้แย้งแยกใน paper

### Step 3: Sensitivity Score

```
Ω = Σ_f w_f · φ_f  ∈ [0,1]
```

คำนวณจาก `ℳ` ที่ประกาศไว้ตั้งแต่ Phase II ไม่ใช่จากสิ่งที่ผู้ร้องขอกรอกตอนขอ

### Step 4: Tier Assignment — แกน governance

```
τ = H   ถ้า Ω ≥ ζ₂
    M   ถ้า ζ₁ ≤ Ω < ζ₂
    L   ถ้า Ω < ζ₁
```

node ยกระดับ `τ` ขึ้นได้ แต่ลดลงไม่ได้

### Step 5: Shard Assignment — แกน concurrency

```
s = H(record_id) mod S ,   tier T ใช้ s mod S_T
```

derive จาก `record_id` อย่างเดียว ทำให้ serialization domain ของ record หนึ่ง ๆ คงที่ข้าม tier และข้าม round

### Step 6: Pre-Filter (off-chain, untrusted)

ตรวจ `old_hash` ยังใหม่ · `policy_id` มีจริง · nullifier ยังไม่ถูกใช้ · `PendingIndex[s][record_id]` ว่าง — **ไม่แตะ `π_P`** ตัวกรองนี้ผิดพลาดได้โดยไม่กระทบ soundness

### Step 7: Dependency Hold

คำขอที่ record มี redaction ค้างอยู่ ต้องรอ **ก่อน**สร้าง proof ไม่ใช่หลัง — เพราะ `old_hash` จะเปลี่ยน ทำให้ proof ที่สร้างไปแล้วเสียเปล่า

### Step 8: Adaptive Round Scheduling

```
Δ_R = f( |Q_R|, max_wait, MPC readiness )

round ปิดเมื่อ:  Δ_R หมด  ∨  |Q_R| ≥ Round_Limit  ∨  deadline[T] ใกล้ถึง
```

round ทำงานแบบ pipeline: `R` execute ขณะ `R+1` aggregate ขณะ `R+2` รับคำขอ tier `T` ถูกเลื่อนทั้ง tier ไป `R+1` ถ้า node ที่พร้อม `< t_mpc[T]` — เลื่อน ไม่ผ่อนเกณฑ์

**Output**

```
𝓡_R = ( Q_R, {(τᵢ, sᵢ)}, {Adm_τ(R)} )
```

ไม่มี `bcn_R` ไม่มี `ℰ_R` ไม่มี VRF proof

> **ตัวอย่าง.** สมชายขอลบ `natid` และ `addr` แต่เก็บ `name` ไว้
> ```
> m′^E = { name: "สมชาย พ.", natid: ⊥, addr: ⊥ }
> ```
> circuit ตรวจ ⑤ ว่า `c^F′ = c^F = 0x7a3f…` → ผ่าน เพราะ `org/type/opened` ไม่ถูกแตะ
> ตรวจ ⑦: `2014-03-14 + 10y = 2024-03-14 < 2026-08-27` → พ้นระยะแล้ว
> ตรวจ ⑥: `rec_8842 ∉ LegalHoldRegistry` → ไม่ติด hold
>
> คะแนน sensitivity
> ```
> w = ( w_typ, w_scope, w_age, w_vol ) = ( 0.40, 0.25, 0.15, 0.20 )
> φ = ( 0.90 , 0.80   , 0.30  , 0.25  )          ← KYC, cross-org, 12 ปี, 1 record
> Ω = 0.40(0.90) + 0.25(0.80) + 0.15(0.30) + 0.20(0.25) = 0.655
> ```
> `Ω = 0.655 ≥ ζ₂ = 0.65` → **τ = H** (ต้องการ 9 node)
> ```
> s = H(rec_8842) mod 6 = 4 ,   tier H: 4 mod S_H = 4 mod 2 = 0
> ```
> คำขอเข้า cell `B(H, 0)` ของ round `R = 417`
>
> **ถ้าสมชายพยายามโกง** โดยยื่น `m′` ที่เปลี่ยน `opened` เป็น 2020 เพื่อให้ดูเหมือนเปิดบัญชีทีหลัง: `c^F′ = H({BankA, KYC, 2020-…} ‖ s^F) ≠ c^F` → conjunct ⑤ ล้ม → **สร้าง proof ไม่ได้ตั้งแต่แรก** ไม่ต้องรอให้ node ปฏิเสธ
>
> **ถ้าธนาคาร A พยายามลบ** record ของสมชายเพื่อทำลายหลักฐาน: ธนาคารไม่ได้ถือ `sk` ของสมชาย → conjunct ② ล้ม ธนาคารเป็นผู้ submit แต่ไม่ใช่ผู้ควบคุมสิทธิ์แก้ไข

---

## Phase IV — Batch Authorization over the (τ, s) Partition

### Step 1: Two-Dimensional Partition

```
B_{τ,s} = { i ∈ Q_R : τᵢ = τ ∧ sᵢ = s } ,     Q_R = ⊔_τ ⊔_s B_{τ,s}
```

```
        s=0     s=1     s=2     s=3     s=4     s=5
      ┌───────┬───────┬───────┬───────┬───────┬───────┐
  H   │ B(H,0)│ B(H,1)│       │       │       │       │  S_H = 2
      ├───────┼───────┼───────┼───────┼───────┼───────┤
  M   │ B(M,0)│ B(M,1)│ B(M,2)│ B(M,3)│       │       │  S_M = 4
      ├───────┼───────┼───────┼───────┼───────┼───────┤
  L   │ B(L,0)│ B(L,1)│ B(L,2)│ B(L,3)│ B(L,4)│ B(L,5)│  S_L = 6
      └───────┴───────┴───────┴───────┴───────┴───────┘
```

แกนใดแกนหนึ่งอย่างเดียวไม่พอ และความล้มเหลวไม่สมมาตร: แบ่งด้วย shard อย่างเดียว → **ไม่ sound** เพราะ batch ที่ปน tier ไม่มี quorum เดียวที่ attest ได้ถูกต้อง; แบ่งด้วย tier อย่างเดียว → แค่**ช้า** ไม่ผิด

### Step 2: L0 — Cell Proofs

หนึ่ง aggregated proof ต่อหนึ่ง `(τ, s)` สร้างขนานกัน คำขอที่ชี้ไปยัง block เดียวกันใช้ sibling path ร่วมกัน ทำให้ circuit เล็กลง

### Step 3: Challenge Derivation

```
ρ_chal = FS( ϱ_{τ,s} ‖ blk_R ‖ R )
```

ห้าม aggregator เลือกเอง — challenge ที่เลือกได้ทำให้ leaf ที่ไม่ valid หักล้างกันหายไปได้ ยังคงใช้ block hash เหมือนเดิม **ไม่ต้องใช้ beacon** เพราะนี่ไม่เคยเป็นหน้าที่ของ beacon อยู่แล้ว

### Step 4: Cross-Tier Nullifier Uniqueness

พิสูจน์ monotonicity ของ nullifier ที่เรียงแล้ว **ภายใน** การ aggregate ครอบทุก cell

```
∀ i < j :  nf_(i) < nf_(j)
```

จำเป็นเพราะคำขอสองรายการบน record เดียวกันอยู่ shard เดียวกันเสมอ แต่**อาจอยู่คนละ tier** จึงอยู่คนละ cell คนละ proof — soundness ระดับ leaf มองไม่เห็นการชนกันนี้

### Step 5: Failure Resolution

- tier H → validity bitmap (ต้นทุนคงที่ ไม่ขึ้นกับพฤติกรรมผู้โจมตี)
- tier L → bisection พร้อม submission bond

partition จำกัดรัศมีความเสียหาย: leaf เสียหนึ่งตัวทำให้ **หนึ่ง cell** ล้ม ไม่ใช่ทั้ง tier

### Step 6: L1 — Fold Shards Within Tier

```
root_T = Fold( { π_{T,s} }_{s < S_T} ) ,   T ∈ {H, M, L}
```

ต้อง fold shard ก่อน tier เสมอ เพราะถ้า fold tier ก่อน จะทำลาย root เดียวที่ attest ได้ที่ quorum เฉพาะของ tier นั้น

### Step 7: Node Attestation *(แทนที่ endorsement + tally เดิม)*

node จำนวน `t_mpc[T]` ตรวจ `root_T` แล้วลงนามร่วม

```
Att_T = ThreshSig_{t_mpc[T]} ( root_T ‖ τ ‖ t_mpc[T] ‖ e ‖ R ‖ ctr )
```

ไม่มี per-item bitmap ไม่มีการนับคะแนน — ความถูกต้องมาจาก proof ไม่ใช่จากการรีวิวของมนุษย์ เซต `𝒳_R` ของรายการที่ผ่านถูกกำหนดโดย validity bitmap จาก Step 5 ไม่ใช่โดยการลงมติ

### Step 8: L2 — Fold Across Tiers

```
root_R = Fold( root_H, root_M, root_L ) ,  พร้อม π_L2
```

### Step 9: Rejection Handling

เผยแพร่การปฏิเสธเป็น aggregate `Ξ^rej_R` พร้อม reason code แบบจัดกลุ่มเท่านั้น — บันทึกรายรายการจะเชื่อมองค์กรเข้ากับความพยายามลบข้อมูลที่ล้มเหลวรายการหนึ่งได้

**Output**

```
Cert_R = ( { root_T, t_mpc[T], Att_T }, root_R, π_L2, 𝒳_R, Ξ^rej_R, ctr )
```

> **ตัวอย่าง.** round 417 มี `|Q| = 1,412` คำขอ กระจายเป็น `B(H,0) = impact 63 รายการ` (รวมของสมชาย) node 9 ตัวจาก 12 ตรวจ `root_H` แล้วออก `Att_H` ส่วน tier L ต้องการเพียง 6 ตัว ถ้าคืนนั้นมี node ออนไลน์แค่ 8 ตัว → **tier H ทั้ง tier ถูกเลื่อนไป round 418** ขณะที่ M และ L เดินหน้าต่อได้

---

## Phase V — Threshold Redaction Execution

### Step 1: Quorum Precheck

```
∀T : Vf( Att_T, root_T, t_mpc[T] ) = 1
```

ไม่มีการเข้าถึง trapdoor material ใด ๆ ก่อนขั้นนี้ผ่าน

### Step 2: Derive Target Syndrome

สร้าง Merkle root ใหม่จาก leaf ที่แก้แล้ว

```
ℓ′ = H( c^F ‖ c^E′ ) ,   ρ′ = MT.Root( …, ℓ′, … )

y = c − H_q( u ‖ ρ′ ) = A·r + H_q(u ‖ ρ) − H_q(u ‖ ρ′)
```

### Step 3: Threshold Collision Computation

หา `r′` ที่ทำให้ commitment เดิมยังใช้ได้กับเนื้อหาใหม่

```
A · r′ = y   (mod q)   ∧   ‖r′‖₂ ≤ β
```

คำนวณแบบ threshold ผ่าน MPC โดย node `t_mpc[τ]` ตัวใช้ share `Rᵢ` ของตน ร่วมกับ preprocessing `𝒫ⱼ` — `R` ยังไม่เคยถูกประกอบขึ้นจริง

```
r′ = Σᵢ∈𝒬 [[r′ᵢ]] ,   |𝒬| = t_mpc[τ]
```

### Step 4: Round Proof Assembly

```
π_R = Prove( { (u, c, ρ, ρ′, r′) }, root_R )
```

### Step 5: On-Chain Verification

```
Acc(R) = V₁′ ∧ V₂ ∧ V₃ ∧ V₄ ∧ V₅ ∧ V₆ ∧ V₇ ∧ V₈
```

| | ตรวจอะไร |
|---|---|
| **V₁′** | node attestation ครบ `t_mpc[τ]` ของทุก tier root *(เดิมคือ VRF sortition)* |
| V₂ | epoch freshness — กันการสวมรอยด้วยกุญแจหมดอายุ |
| V₃ | norm check `‖r′‖₂ ≤ β` |
| V₄ | nullifier ไม่ซ้ำและถูก insert |
| **V₅** | **provenance guard — `c^F` ยังเป็นค่าเดิมทุกไบต์** |
| V₆ | Merkle openings `ρ′` ↔ `ℓ′` |
| V₇ | public-parameter anchor `H(A_pub)` ตรงกับที่ลงทะเบียน |
| V₈ | aggregated collision `A·r′ + H_q(u ‖ ρ′) = c` |

`V₅` เป็นการตรวจเดียวที่**ไม่ขึ้นกับผู้ร้องขอเลย** — แม้ผู้ร้องขอจะควบคุม input ทุกอย่าง ก็ยังผ่าน `V₅` ไม่ได้ถ้าแตะ provenance

### Step 6: Erasure

```
𝒟 : delete s^E , delete k
```

`ct` ที่เหลืออยู่กลายเป็นข้อมูลที่ถอดไม่ได้ และ `c^E` เดิมเปิดไม่ได้เพราะไม่มี salt — การลบเหลือแค่การลบสองค่า ไม่ต้องไล่ลบทั้งระบบ

### Step 7: State Advance

```
CurrentState( record_id ) ← ℓ′ ,  version ← version + 1
PendingIndex[s].remove( record_id )
```

> **ตัวอย่าง.** node 9 ตัวคำนวณ `r′` ร่วมกันโดยไม่มีใครเห็น `R` เต็ม ผลลัพธ์บน chain:
> ```
> c        = 0x4f8d…     ← เท่าเดิม ไม่เปลี่ยน block hash ไม่ต้อง fork
> c^F      = 0x7a3f…     ← เท่าเดิม  "BankA เปิด KYC เมื่อ 2014-03-14" ยังพิสูจน์ได้
> c^E      : 0xc21b… → 0x1d90…
> ct, k, s^E : ลบแล้ว    ← natid และ addr ของสมชายกู้คืนไม่ได้
> ```
> regulator ยังตรวจได้ว่าธนาคาร A มีลูกค้า KYC รายหนึ่งเปิดบัญชีปี 2014 และมีการลบข้อมูลเกิดขึ้นเมื่อใด โดยที่ตัวข้อมูลส่วนบุคคลหายไปจริง

---

## Phase VI — Privacy-Preserving Redaction Auditing

### Step 1: Certificate Generation

```
Ψ_i = ( record_id, R, τ, ℓ → ℓ′, Att_τ, path, hold_root_R )
```

### Step 2: Verification

```
W₁ : Merkle inclusion ของ ℓ′ ใน root_R
W₂ : redaction ได้รับ attestation ที่ t_mpc[τ]        (เดิม: quorum ≥ θ_τ)
W₃ : lawfulness predicate เป็นจริง ณ เวลาที่ร้องขอ     (เดิม: VRF proof ถูกต้อง)
W₄ : τ = Tier( Ω(ℳ) )                                 คำนวณซ้ำจาก ℳ ที่ commit ไว้
```

`W₃` ตรวจกับ `hold_root` **ในอดีต ณ round R** ดังนั้นต้องเก็บ `hold_root` ไว้ใน `AuditEvt_R` ร่วมกับ state อื่นของ round นั้น มิฉะนั้นการปลด hold ในภายหลังจะทำให้ audit ย้อนหลังตัดสินผิด

### Step 3: Disclosure Properties

auditor เห็น: มี redaction เกิดขึ้น, tier ใด, ผ่าน quorum เท่าใด, ชอบด้วยกฎหมายหรือไม่
auditor **ไม่เห็น**: `m^E` เดิม, ตัวตนของ subject, `m′` ใหม่

### Step 4: Audit Modes

| mode | ขอบเขต |
|---|---|
| Single-item | ตรวจ `Ψ_i` หนึ่งใบ |
| Round-level | ตรวจ `Cert_R` ทั้ง round |
| Continuous | replay ทุก round ที่ commit แล้ว เทียบกับ policy ที่ลงทะเบียนไว้ |

**ขนาด certificate**

```
เดิม :  Ψ + 103 VRF proofs × 80 B   ≈  8.7 KB
ใหม่ :  Ψ + threshold signature 1 ใบ ≈  0.6 KB      (≈ 14×)
```

---

## สรุปการแลกเปลี่ยน

**ได้:** โปรโตคอลง่ายลงมาก · ไม่มี liveness dependency กับ endorser จำนวนมาก · certificate เล็กลง ~14 เท่า · ไม่มีการเลื่อนรอบเพราะ committee ไม่ครบ · และเล่าเรื่องได้ตรงกว่า — "เจ้าของข้อมูลควบคุมข้อมูลของตนเอง" ป้องกันง่ายกว่า "คณะกรรมการที่สุ่มมาเป็นผู้ตัดสิน"

**เสีย:**

1. **dual-layer authorization หายไป** — 𝒩 ถือทั้งกุญแจและอำนาจ ผู้โจมตีที่คุม `t_mpc[H] = 9` node ได้ทุกอย่าง เดิมต้องคุมทั้ง node และ endorser
2. **ไม่มีดุลยพินิจมนุษย์** — ทุกอย่างต้อง encode เป็น on-chain predicate ได้ กรณี PDPA ที่ registry ไม่ครอบคลุมจะจัดการไม่ได้เลย
3. **ข้อโต้แย้งเรื่อง partition อ่อนลง** — ยังถูกอยู่ แต่ "quorum สำหรับ reconstruct กุญแจ" เป็นแกน governance ที่อ่อนกว่า "จำนวนคนที่รีวิว" reviewer อาจถามว่าทำไมไม่ attest ทั้ง batch ที่ `max(t_mpc)` ไปเลย

ข้อ 3 คือข้อที่ต้องคิดหนักที่สุด ถ้าจะให้ partition ยัง load-bearing ต้องแสดงว่าการ attest ที่ `max(t_mpc)` ไม่ยอมรับได้ — ซึ่งน่าจะเป็นข้อโต้แย้งเชิงต้นทุน (over-provision การมีส่วนร่วมของ node สำหรับคำขอ tier ต่ำ) ที่อ่อนกว่าข้อโต้แย้งเชิง soundness เดิม ทางเลือกอีกทางคือคง approval quorum ต่อ tier ไว้ในมือของฝ่ายที่แยกจาก 𝒩 โดยใช้ **committee คงที่แบบไม่ต้องสุ่ม** — การเอา beacon ออกไม่จำเป็นต้องเอา ℰ ออกทั้งหมด แค่หมายความว่า `ℰ_R = ℰ` หรือหมุนตามตารางแทนการสุ่ม
