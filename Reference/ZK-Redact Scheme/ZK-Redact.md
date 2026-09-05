::: IEEEkeywords
Redactable Blockchain, Zero-Knowledge Proof, Verifiable Redaction,
Redaction Provenance, Integrity Auditing, Permissioned Blockchain.
:::

# Introduction {#sec:introduction}

Permissioned blockchains provide shared and tamper-evident records for
multi-organization applications. However, strict immutability can
conflict with practical requirements such as correcting erroneous data,
removing sensitive information, or satisfying privacy regulations.
Redactable blockchains address this limitation by enabling authorized
modification while preserving ledger consistency, commonly using
chameleon hashes (CHs) [@ref1; @ref2; @ref9]. Recent studies have
extended CH-based redaction with decentralized authorization,
fine-grained access control, anonymity, dynamic updates, and
verifiability [@ref4; @ref6; @ref14; @ref15; @ref16; @ref20].

Despite these advances, supporting *large-scale* privacy-preserving
redaction remains challenging. First, *privacy-preserving authorization
can become a verification bottleneck*. Anonymous and privacy-preserving
redaction mechanisms protect requester identity or authorization
information [@ref4; @ref14; @ref17], but independently processing
cryptographic authorization evidence for many concurrent requests
increases verification overhead. Existing scalability-oriented schemes
mainly optimize blockchain structures or redaction processing
[@ref10; @ref14; @ref21], leaving scalable privacy-preserving
authorization under massive concurrent requests insufficiently
addressed.

Second, *redaction execution can become computationally expensive at
scale*. CH-based schemes require authorized collision computation and
ledger-state updates for each modification
[@ref1; @ref2; @ref6; @ref19], while policy enforcement, distributed
authorization, and accountability introduce additional processing
[@ref3; @ref15; @ref20]. In permissioned implementations, individually
processing each validated request may further repeat chaincode,
transaction, and ledger-update operations. Consequently, large redaction
workloads require an efficient mechanism for organizing validated
requests and amortizing common blockchain-processing overhead.

Third, *efficient verification of redaction history remains
challenging*. Since a valid CH redaction preserves blockchain linkage,
the current ledger state alone does not reveal how a transaction has
evolved. Existing schemes support traceability, integrity auditing, and
authenticated redaction structures [@ref10; @ref13; @ref16; @ref20];
however, verifying multiple successive redactions may still require
locating and examining their corresponding historical records. Efficient
auditing therefore requires authenticated provenance that supports
direct retrieval and compact verification of both individual redactions
and the continuity of a transaction's redaction history.

To address these challenges, we propose **ZK-Redact**, a
privacy-preserving framework for scalable redaction and provenance
auditing in permissioned blockchains. ZK-Redact uses state- and
policy-bound zero-knowledge proofs (ZKPs) for redaction authorization
without revealing private credentials or attributes. Logical proof
shards distribute ZKP verification across parallel workers, with
intra-shard batching when supported. Verified requests are then
batch-organized for CH-based redaction, reducing common chaincode and
ledger-processing overhead. Finally, transaction-specific hash-linked
provenance is Merkle-authenticated and blockchain-anchored, enabling
efficient retrieval and independent verification of redaction history.

The main contributions are summarized as follows:

- **Sharded Privacy-Preserving ZK Authorization:** We introduce state-
  and policy-bound ZK authorization with logical proof sharding for
  parallel verification. Intra-shard batching further amortizes
  verification when supported, reducing ZKP bottlenecks while preserving
  request-level authorization and failure isolation.

- **Optimized Batch Redaction Processing:** We separate ZKP verification
  from redaction execution and batch successfully verified requests for
  processing. State revalidation prevents stale redactions, while common
  chaincode, validation, and ledger operations are amortized without
  aggregating request-specific CH computations.

- **Authenticated Provenance and Verifiable Auditing:** We combine
  transaction-specific hash-linked histories, Merkle-authenticated
  entries, and blockchain-anchored commitments to support direct
  provenance retrieval and independent verification of ZKP
  authorization, history completeness, ordering, and state continuity
  without exhaustive blockchain traversal.

# Related Work {#sec:related}

Existing redactable blockchain research has primarily addressed
controlled modification, decentralized authorization, privacy, and
verifiability. Ateniese *et al.* [@ref9] established the foundation for
blockchain rewriting using chameleon hashes (CHs), while Huang *et
al.* [@ref2] extended controlled redaction to consortium blockchains for
Industrial Internet of Things (IIoT) environments. Subsequent schemes
have reduced dependence on a single trapdoor holder through
decentralized or distributed CH constructions
[@ref1; @ref6; @ref12; @ref19]. Fine-grained redaction has also been
investigated through attribute- and policy-based mechanisms
[@ref8; @ref15; @ref18], while dynamic redaction and trust-aware
authorization have been considered in [@ref5; @ref16]. These schemes
strengthen control over *who* can modify blockchain data, but their
primary focus is secure redaction rather than optimizing the complete
authorization and redaction pipeline under massive concurrent requests.

Privacy and accountability introduce additional requirements. Huang *et
al.* [@ref14] proposed scalable redaction with anonymity, while
PriChain [@ref4] supports privacy-preserving fine-grained redaction in
decentralized settings. More recently, Wang *et al.* [@ref17] considered
anonymous and accountable data redaction for IIoT. These approaches
demonstrate the importance of protecting requester information while
retaining redaction accountability. However, privacy-preserving
authorization introduces additional cryptographic processing, and the
cited works do not directly address the use of *proof sharding with
batch ZKP verification* for distributing large concurrent authorization
workloads. ZK-Redact focuses on this scalability dimension by
partitioning independently authenticated proofs across logical shards
and processing them in parallel and in batches.

Scalability has also been studied from the redaction and data-structure
perspectives. Huang *et al.* [@ref14] considered scalable redactable
blockchains with update support, while Wu *et al.* [@ref10] introduced
an extended Merkle tree for inserted-data redaction in permissioned
blockchains. Fugkeaw *et al.* [@ref21] further investigated efficient
redaction for large-scale GDPR-compliant blockchain-based e-KYC. Other
schemes support dynamic redaction [@ref5; @ref19], decentralized CH
operations [@ref1; @ref6], and multi-party CH constructions [@ref12].
Nevertheless, individually executing authorization, CH-related
operations, and blockchain updates can still incur repeated processing
as the number of redaction requests grows. In contrast, ZK-Redact
separates ZKP authorization from redaction execution and organizes
already-validated requests for batch-oriented processing, thereby
reducing repeated chaincode and ledger-processing operations.

Verifiability and traceability constitute another important research
direction. VRBC [@ref13] provides verifiable redaction with efficient
query and integrity auditing, while Zhang *et al.* [@ref16] support
update and traceability through dynamic trust-based redaction. Miao *et
al.* [@ref20] further combine verifiable redaction with lightweight
storage and permission supervision. ReAcct [@ref11] considers redaction
control in interoperable blockchain environments, and authenticated tree
structures such as EMT [@ref10] improve verification of modified
blockchain data. These mechanisms provide important foundations for
redaction accountability and integrity verification. However,
efficiently retrieving and verifying the *successive provenance history
of a particular transaction* remains a distinct requirement: an auditor
should be able to determine the ordered sequence of redactions and
verify continuity between previous and resulting states without
exhaustively traversing blockchain records.

In summary, existing work provides strong foundations for controlled
CH-based redaction, privacy-preserving authorization, scalable redaction
structures, and integrity auditing. ZK-Redact complements these
directions by jointly addressing three processing stages that become
critical under large-scale workloads: *(i)* sharded batch ZKP
verification for scalable privacy-preserving authorization, *(ii)*
batch-oriented processing of independently validated redactions, and
*(iii)* authenticated provenance organization for efficient retrieval
and verification of successive redaction history.

# The Proposed ZK-Redact Framework {#sec:scheme}

This section presents the system model, threat model, and construction
of ZK-Redact. The framework is designed to efficiently process
privacy-preserving redaction requests while preserving verifiable
provenance for subsequent auditing.

## System Model {#sec:system}

ZK-Redact operates over a permissioned blockchain shared by multiple
organizations. As shown in
Fig. [1](#fig:system_model){reference-type="ref"
reference="fig:system_model"}, it consists of six components: *Requester
(RQ)*, *Redaction Gateway (RG)*, *Proof Verification Layer (PVL)*,
*Permissioned Blockchain (PB)*, *Provenance Audit Index (PAI)*, and
*Auditor (AU)*.

<figure id="fig:system_model" data-latex-placement="t">
<img src="./zk_redact_system_model.PNG" />
<figcaption>System model of the proposed ZK-Redact
framework</figcaption>
</figure>

1.  **Requester (RQ):** A registered user or organization requesting
    modification of a blockchain transaction. The RQ constructs the
    redaction request and generates a zero-knowledge proof (ZKP)
    demonstrating compliance with the applicable redaction policy
    without revealing private authorization information.

2.  **Redaction Gateway (RG):** The RG serves as the admission-control
    layer. It authenticates and pre-validates incoming requests, filters
    stale or duplicate requests, and removes unnecessary
    requester-identifying information before forwarding accepted
    requests to the proof-verification layer.

3.  **Proof Verification Layer (PVL):** The PVL provides scalable ZKP
    authorization verification. It distributes accepted proofs across
    logical proof shards for parallel processing and supports
    intra-shard batched verification when available. Only successfully
    verified requests proceed to redaction.

4.  **Permissioned Blockchain (PB):** The PB maintains transactions,
    redaction policies, and authenticated redaction states. It executes
    verified redactions using CH-based modification and organizes
    validated requests for batch-oriented blockchain processing to
    reduce common chaincode and ledger overhead.

5.  **Provenance Audit Index (PAI):** The PAI maintains authenticated,
    transaction-specific redaction histories. It cryptographically links
    successive redaction states and uses a Merkle-based commitment
    anchored on the PB to support efficient provenance retrieval and
    integrity verification.

6.  **Auditor (AU):** The AU retrieves and independently verifies the
    provenance of a target transaction. It validates redaction
    authorization, history integrity and completeness, and
    successive-state continuity without accessing private ZKP witnesses
    or traversing unrelated blockchain records.

## System Process {#sec:system-process}

ZK-Redact operates through sequential phases covering system setup,
privacy-preserving authorization, sharded ZKP verification, batch
redaction, provenance maintenance, and audit verification.

### **Phase 1: System Setup** {#sec:phase1 .unnumbered}

This phase initializes the cryptographic, authorization,
proof-processing, blockchain, and provenance components of ZK-Redact.

**Step 1: System and Entity Initialization**

The system administrator initializes $$\begin{equation}
PP=(H,\mathsf{Sig},\mathsf{CH},\mathsf{ZK},
N,B,\Delta,B_R,\Delta_R)
\label{eq:pp}
\end{equation}$$ where $H$ is a collision-resistant hash function;
$\mathsf{Sig}$, $\mathsf{CH}$, and $\mathsf{ZK}$ denote the signature,
chameleon-hash, and zero-knowledge proof schemes; $N$ is the number of
proof shards; and $(B,\Delta)$ and $(B_R,\Delta_R)$ specify the size and
waiting bounds for proof-verification and redaction batches,
respectively.

Each requester $U_i$ generates $$\begin{equation}
(pk_i,sk_i)\leftarrow\mathsf{Sig.KeyGen}(1^\lambda)
\label{eq:user-keygen}
\end{equation}$$ and registers $E_i=(ID_i,pk_i)$, while retaining $sk_i$
for request authentication.

Similarly, each auditor $AU_a$ generates $$\begin{equation}
(pk_a,sk_a)\leftarrow\mathsf{Sig.KeyGen}(1^\lambda)
\label{eq:auditor-keygen}
\end{equation}$$ and registers $$\begin{equation}
E_a^{\mathrm{AU}}
=
(AID_a,pk_a,\mathcal{P}_a^{\mathrm{audit}})
\label{eq:auditor-registration}
\end{equation}$$ where $\mathcal{P}_a^{\mathrm{audit}}$ specifies its
permitted audit scope. These registered credentials are subsequently
used to authenticate and authorize provenance queries in Phase 6.

**Step 2: Redaction Policy Registration**

For each protected transaction class, the policy administrator defines
$$\begin{equation}
P_j=(PID_j,\mathcal{A}_j,\mathcal{C}_j,\mathcal{S}_j,V_j)
\label{eq:redaction-policy}
\end{equation}$$ where $\mathcal{A}_j$, $\mathcal{C}_j$,$\mathcal{S}_j$,
and $V_j$ specify the authorization predicates, additional conditions,
permitted redaction scope, and validity period. Its commitment
$$\begin{equation}
C_{P_j}
=
H(PID_j\parallel\mathcal{A}_j\parallel\mathcal{C}_j
\parallel\mathcal{S}_j\parallel V_j)
\label{eq:policy-commitment}
\end{equation}$$ is recorded on the blockchain and subsequently bound to
the public ZKP statement.

**Step 3: ZKP and Chameleon-Hash Setup**

The system generates $$\begin{equation}
(pp_{\mathrm{zk}},vk_{\mathrm{zk}})
\leftarrow
\mathsf{ZK.Setup}(1^\lambda,\mathcal{R}_{\mathrm{red}})
\label{eq:zk-setup}
\end{equation}$$ where $\mathcal{R}_{\mathrm{red}}$ defines
policy-compliant redaction authorization. The proving parameters
$pp_{\mathrm{zk}}$ are available to requesters, while $vk_{\mathrm{zk}}$
is provided to the PVL.

The CH parameters are generated as $$\begin{equation}
(pk_{\mathrm{ch}},tk_{\mathrm{ch}})
\leftarrow
\mathsf{CH.KeyGen}(1^\lambda)
\label{eq:ch-setup}
\end{equation}$$ where $tk_{\mathrm{ch}}$ is protected by the trusted
redaction component and used only for authorized CH adaptation.

**Step 4: Blockchain and Proof-Shard Initialization**

The permissioned blockchain deploys chaincode for entity and policy
registration, audit-access authorization, transaction updates, redaction
results, and provenance commitments. The PVL initializes
$$\begin{equation}
\mathbb{S}
=
\{\mathcal{S}_1,\mathcal{S}_2,\ldots,\mathcal{S}_N\}
\label{eq:proof-shards}
\end{equation}$$ where each $\mathcal{S}_j$ maintains an independent
proof queue. Runtime shard assignment and verification-batch formation
are performed in Phase 3.

**Step 5: Provenance Audit Index Initialization**

For each transaction $TID_i$ with authenticated initial state
$T_i^{(0)}$, the PAI initializes $$\begin{equation}
v_i=0,\qquad
\mathcal{H}_i^{(0)}=\emptyset
\label{eq:initial-history}
\end{equation}$$ and computes $$\begin{equation}
d_i^{(0)}=H(T_i^{(0)})
\label{eq:initial-state-digest}
\end{equation}$$ $$\begin{equation}
c_i^{(0)}
=
H(TID_i\parallel0\parallel d_i^{(0)})
\label{eq:initial-provenance}
\end{equation}$$ The corresponding authenticated entry is
$$\begin{equation}
A_i^{(0)}
=
H(TID_i\parallel0\parallel c_i^{(0)})
\label{eq:initial-pai-entry}
\end{equation}$$ and the initial PAI root is $$\begin{equation}
R_{\mathrm{PAI}}^{(0)}
=
\mathsf{MerkleRoot}
\left(
\left\{A_i^{(0)}\right\}_{i\in\mathcal{I}}
\right)
\label{eq:initial-pai-root}
\end{equation}$$ where $\mathcal{I}$ is the set of indexed transactions.
$R_{\mathrm{PAI}}^{(0)}$ is anchored to the permissioned blockchain as
the trusted initial provenance state.

### **Phase 2: Redaction Request and Privacy-Preserving Authorization** {#phase-2-redaction-request-and-privacy-preserving-authorization .unnumbered}

This phase authenticates each redaction request, proves policy
compliance without revealing private authorization attributes, and
filters invalid, stale, or duplicate requests before ZKP verification.

**Step 1: Redaction Request and Authentication**

For target transaction $TID_i$ at version $v_i$, requester $U_i$
constructs $$\begin{equation}
R_i=(TID_i,v_i,Loc_i,M_i,PID_i,t_i,\nu_i)
\label{eq:redaction-request}
\end{equation}$$ where $Loc_i$ and $M_i$ specify the target location and
modification, $PID_i$ identifies the applicable policy, and
$(t_i,\nu_i)$ provides freshness. The requester authenticates the
request by $$\begin{equation}
\sigma_i=
\mathsf{Sig.Sign}\!\left(sk_i,H(R_i)\right)
\label{eq:request-signature}
\end{equation}$$ binding it to the target state, operation, policy, and
freshness information.

**Step 2: Policy- and State-Bound ZK Authorization**

The requester obtains the current policy version $v_{P_i}$ and
commitment $C_{P_i}$, and constructs the public ZKP statement
$$\begin{equation}
x_i=
(TID_i,v_i,Loc_i,M_i,PID_i,v_{P_i}
C_{P_i},t_i,\nu_i)
\label{eq:zk-statement}
\end{equation}$$ with compact binding digest $$\begin{equation}
\eta_i=H(x_i)
\label{eq:statement-digest}
\end{equation}$$ The private witness is $$\begin{equation}
w_i=(Cred_i,\mathcal{A}_i,\rho_i)
\label{eq:zk-witness}
\end{equation}$$ where $Cred_i$ is the requester's credential,
$\mathcal{A}_i$ its private authorization attributes, and $\rho_i$
auxiliary credential evidence.

The authorization relation $$\begin{equation}
\mathcal{R}_{\mathrm{red}}(x_i,w_i)=1
\label{eq:authorization-relation}
\end{equation}$$ holds iff $Cred_i$ is valid and non-revoked,
$\mathcal{A}_i$ satisfies the predicates represented by $C_{P_i}$,
$(Loc_i,M_i)$ is within the permitted scope, and the transaction and
policy versions and freshness values are valid. Thus, the proof is bound
to the specific redaction request and its governing policy.

The requester generates $$\begin{equation}
\pi_i\leftarrow
\mathsf{ZK.Prove}(pp_{\mathrm{zk}},x_i,w_i)
\label{eq:zk-proof}
\end{equation}$$ and submits $$\begin{equation}
Q_i=(R_i,v_{P_i},C_{P_i},\sigma_i,\pi_i)
\label{eq:redaction-query}
\end{equation}$$ to the Redaction Gateway (RG).

**Step 3: Gateway Pre-Validation and Deduplication**

The RG retrieves the registered $pk_i$ and verifies $$\begin{equation}
\mathsf{Sig.Verify}(pk_i,H(R_i),\sigma_i)=1
\label{eq:signature-verification}
\end{equation}$$ It then validates $(t_i,\nu_i)$, confirms that $v_i$ is
the current transaction version, and checks the registered policy tuple
$(PID_i,v_{P_i},C_{P_i})$. Invalid or stale requests are rejected before
ZKP verification.

For each accepted request, the RG computes $$\begin{equation}
DID_i=
H(TID_i\parallel v_i\parallel Loc_i
\parallel M_i\parallel PID_i)
\label{eq:deduplication-id}
\end{equation}$$ and accepts it only if $$\begin{equation}
DID_i\notin\mathcal{P}_{\mathrm{req}}
\label{eq:duplicate-check}
\end{equation}$$ where $\mathcal{P}_{\mathrm{req}}$ contains pending or
previously processed identifiers. The accepted $DID_i$ is then inserted
into $\mathcal{P}_{\mathrm{req}}$. Including $v_i$ prevents duplicate
processing against the same transaction state while permitting a new
redaction after the state advances.

**Step 4: Identity-Minimized Downstream Submission**

After pre-validation, the RG removes the explicit requester identity and
constructs $$\begin{equation}
Q_i^{*}=
(DID_i,x_i,\eta_i,\pi_i)
\label{eq:identity-minimized-query}
\end{equation}$$ Since $x_i$ already contains the transaction,
operation, policy, version, and freshness information required for
downstream processing, this compact representation avoids duplicating
those fields.

The RG securely retains the mapping between $DID_i$ and the
authenticated requester for accountability, while the PVL and downstream
components receive only $Q_i^{*}$. Thus, explicit requester identity is
hidden from downstream processing without assuming anonymity against the
RG.

The accepted $Q_i^{*}$ is forwarded to Phase 3 for deterministic
proof-shard assignment and parallel ZKP verification.

### **Phase 3: Sharded Batch ZKP Verification** {#sec:phase3 .unnumbered}

This phase distributes accepted ZK authorization proofs across logical
proof shards for parallel verification, combining inter-shard
parallelism with intra-shard batched processing.

<figure data-latex-placement="t">
<img src="./Sequence Diagram.png" />
<figcaption>Sequence of redaction-request verification using distributed
proof shards</figcaption>
</figure>

**Step 1: Proof-Shard Assignment**

For each accepted query $Q_i^{*}$ from Phase 2, the PVL assigns
$$\begin{equation}
j_i=
1+\big(\mathsf{Int}(H(DID_i))\bmod N\big),
\qquad
Q_i^{*}\rightarrow\mathcal{S}_{j_i}
\label{eq:phase3-shard}
\end{equation}$$ where $N$ is the number of logical proof shards. The
hash-based rule provides uniform workload distribution in expectation.
Each shard $\mathcal{S}_j$ maintains an independent verification queue
and is processed concurrently with other active shards.

**Step 2: Shard-Level Batch Formation**

Each active shard forms $$\begin{equation}
\mathcal{B}_j^{(e)}
=
\left\{
(x_i,\pi_i,Q_i^{*})
\right\}_{i\in I_j^{(e)}},
\qquad
|\mathcal{B}_j^{(e)}|\leq B
\label{eq:proof-batch}
\end{equation}$$ where $I_j^{(e)}$ is the set of requests selected in
verification round $e$. A batch closes when $$\begin{equation}
\mathsf{Close}\!\left(\mathcal{B}_j^{(e)}\right)
=
\left(|\mathcal{B}_j^{(e)}|=B\right)
\lor
\left(\tau_j^{(e)}\geq\Delta\right)
\label{eq:batch-close}
\end{equation}$$ where $\tau_j^{(e)}$ is the waiting time of the oldest
request. This permits larger batches under high load while bounding
delay under sparse arrivals.

**Step 3: Parallel ZKP Verification**

Let $\mathcal{J}_e$ denote the active shards in round $e$. Their batches
are processed concurrently, while each request is verified as
$$\begin{equation}
V_i=
\mathsf{ZK.Verify}(vk_{\mathrm{zk}},x_i,\pi_i),
\qquad
V_i\in\{0,1\}
\label{eq:individual-zk-verification}
\end{equation}$$ Thus, proof sharding provides parallelism independently
of any scheme-specific batch-verification capability.

If the instantiated ZKP scheme supports native batch verification, shard
$\mathcal{S}_j$ may instead compute $$\begin{equation}
\mathbf{V}_j^{(e)}
\leftarrow
\mathsf{ZK.BatchVerify}
\left(
vk_{\mathrm{zk}},
\left\{(x_i,\pi_i)\right\}_{i\in I_j^{(e)}}
\right)
\label{eq:native-batch-verify}
\end{equation}$$ where $$\begin{equation}
\mathbf{V}_j^{(e)}
=
\left\{V_i\right\}_{i\in I_j^{(e)}}
\label{eq:verification-vector}
\end{equation}$$ Otherwise, the proofs in $\mathcal{B}_j^{(e)}$ are
independently verified using
([\[eq:individual-zk-verification\]](#eq:individual-zk-verification){reference-type="ref"
reference="eq:individual-zk-verification"}). Hence, native batch
verification is an optional optimization rather than a correctness
requirement.

**Step 4: Failure Isolation and Verified Request Pool**

Verification remains request-specific, and $Q_i^{*}$ is accepted only if
$V_i=1$. If a native batch verifier returns only an aggregate pass/fail
result, a failed batch is recursively divided and reverified until
invalid proofs are isolated. This step is unnecessary when per-proof
results are available.

Successfully verified requests form $$\begin{equation}
\mathcal{P}_{\mathrm{ver}}
=
\left\{
Q_i^{*}\mid V_i=1
\right\}
\label{eq:verified-pool}
\end{equation}$$ $P_{ver}$ is forward to PB while invalid requests are
rejected and their pending identifiers are released according to the
request-management policy.

Phase 3 therefore uses *proof sharding* for parallel ZKP verification
and *intra-shard batching* for efficient scheduling and, when supported,
native batch-verification gains. $\mathcal{P}_{\mathrm{ver}}$ is
forwarded to Phase 4 for redaction execution.

### **Phase 4: Batch-Verified Redaction and Provenance Generation** {#phase-4-batch-verified-redaction-and-provenance-generation .unnumbered}

This phase organizes verified requests for batch-oriented processing,
executes authorized CH redactions, and generates authenticated
provenance evidence. CH adaptation remains request-specific, while
common blockchain operations are amortized across the batch.

**Step 1: Redaction Batch Formation**

Verified requests in $\mathcal{P}_{\mathrm{ver}}$ are organized as
$$\begin{equation}
\mathcal{B}_{R}^{(e)}
=
\left\{Q_i^{*}\right\}_{i\in I_R^{(e)}},
\qquad
|\mathcal{B}_{R}^{(e)}|\leq B_R
\label{eq:redaction-batch}
\end{equation}$$ where $B_R$ is the maximum batch size. A batch closes
when $$\begin{equation}
\mathsf{Close}(\mathcal{B}_{R}^{(e)})
=
\left(|\mathcal{B}_{R}^{(e)}|=B_R\right)
\lor
\left(\tau_R^{(e)}\geq\Delta_R\right)
\label{eq:redaction-batch-close}
\end{equation}$$ Requests targeting different transactions may execute
independently, whereas requests targeting the same transaction are
serialized.

**Step 2: State Revalidation and Execution Commitment**

Immediately before execution, the PB checks $$\begin{equation}
\mathsf{Fresh}_i=
[v_i=v_i^{\mathrm{cur}}]
\land
[v_{P_i}=v_{P_i}^{\mathrm{cur}}]
\label{eq:redaction-revalidation}
\end{equation}$$ where $v_i^{\mathrm{cur}}$ and $v_{P_i}^{\mathrm{cur}}$
are the current transaction and policy versions. A stale request is
excluded and must be reauthorized. For requests targeting the same
transaction, this check is repeated before each transition.

The fresh execution set is $$\begin{equation}
I_F^{(e)}
=
\left\{
i\in I_R^{(e)}:\mathsf{Fresh}_i=1
\right\}
\label{eq:fresh-set}
\end{equation}$$ and is bound to the processing round by
$$\begin{equation}
R_B^{(e)}
=
\mathsf{MerkleRoot}
\left(
\left\{
H(DID_i\parallel\eta_i)
\right\}_{i\in I_F^{(e)}}
\right)
\label{eq:redaction-batch-root}
\end{equation}$$ where $\eta_i=H(x_i)$ is the statement-binding digest
defined in Phase 2.

**Step 3: Authorized CH Redaction**

For each $i\in I_F^{(e)}$, let $m_i^{(v_i)}$ and $r_i^{(v_i)}$ denote
the current content and CH randomness. For modified content
$m_i^{(v_i+1)}$, the trusted redaction component computes
$$\begin{equation}
r_i^{(v_i+1)}
\leftarrow
\mathsf{CH.Adapt}
\left(
tk_{\mathrm{ch}},
m_i^{(v_i)},r_i^{(v_i)},m_i^{(v_i+1)}
\right)
\label{eq:ch-adapt}
\end{equation}$$ such that $$\begin{equation}
\mathsf{CH.Hash}
(pk_{\mathrm{ch}},m_i^{(v_i)},r_i^{(v_i)})
=
\mathsf{CH.Hash}
(pk_{\mathrm{ch}},m_i^{(v_i+1)},r_i^{(v_i+1)})
\label{eq:ch-collision}
\end{equation}$$ The authorized state transition is $$\begin{equation}
T_i^{(v_i)}
\longrightarrow
T_i^{(v_i+1)}
\label{eq:redaction-transition}
\end{equation}$$ Thus, CH adaptation is performed independently, while
batching amortizes common chaincode, validation, commitment, and ledger
processing.

**Step 4: Provenance and Audit-Evidence Generation**

For each successful redaction, ZK-Redact computes $$\begin{equation}
d_i^{\mathrm{old}}=H(T_i^{(v_i)})
\end{equation}$$ $$\begin{equation}
d_i^{\mathrm{new}}=H(T_i^{(v_i+1)})
\label{eq:state-digests}
\end{equation}$$ and binds its authorization evidence by
$$\begin{equation}
C_i^{\mathrm{auth}}
=
H(DID_i\parallel\eta_i\parallel H(\pi_i))
\label{eq:authorization-evidence}
\end{equation}$$ It constructs $$\begin{equation}
\begin{split}
PR_i^{(v_i+1)}
=\big(&TID_i,v_i,v_i+1,PID_i,v_{P_i},DID_i,\\
&d_i^{\mathrm{old}},d_i^{\mathrm{new}},
C_i^{\mathrm{auth}},R_B^{(e)},t_i'\big)
\end{split}
\label{eq:provenance-record}
\end{equation}$$ where $t_i'$ is the completion timestamp. The public
audit evidence $(x_i,\pi_i)$ is retained off-chain under $DID_i$ and
authenticated by $C_i^{\mathrm{auth}}$, enabling independent
verification in Phase 6.

**Step 5: Batch-Result Commitment**

Let $$\begin{equation}
I_{\mathrm{succ}}^{(e)}
\subseteq I_F^{(e)}
\label{eq:successful-set}
\end{equation}$$ denote the successfully executed requests. ZK-Redact
computes $$\begin{equation}
C_B^{(e)}
=
H\left(
R_B^{(e)}\parallel e\parallel
\mathsf{MerkleRoot}
\left(
\left\{
H(PR_i^{(v_i+1)})
\right\}_{i\in I_{\mathrm{succ}}^{(e)}}
\right)
\right)
\label{eq:batch-redaction-commitment}
\end{equation}$$ The PB commits the successful state updates and
$C_B^{(e)}$; stale or failed requests are excluded without affecting
independent successful redactions. The resulting provenance records are
forwarded to the PAI for authenticated maintenance in Phase 5.

Phase 4 therefore separates request-specific CH adaptation from
batch-level blockchain processing, preserving per-request correctness
while reducing common processing overhead.

### **Phase 5: Authenticated Provenance Maintenance** {#phase-5-authenticated-provenance-maintenance .unnumbered}

This phase updates the transaction-specific provenance histories after
each completed redaction batch and anchors the resulting PAI state to
the blockchain. Processing round $e$ corresponds to the successful
batch-result commitment $C_B^{(e)}$ generated in Phase 4.

**Step 1: Provenance-Chain Update**

For each successful redaction $PR_i^{(v_i+1)}$ in round $e$, the PAI
appends $$\begin{equation}
\mathcal{H}_i^{(v_i+1)}
=
\mathcal{H}_i^{(v_i)}
\parallel PR_i^{(v_i+1)}
\label{eq:history-update}
\end{equation}$$ and updates its cumulative commitment as
$$\begin{equation}
c_i^{(v_i+1)}
=
H\left(
c_i^{(v_i)}
\parallel H(PR_i^{(v_i+1)})
\right)
\label{eq:provenance-chain}
\end{equation}$$ where $c_i^{(0)}$ is initialized in Phase 1. Successive
records must satisfy $$\begin{equation}
d_i^{\mathrm{new},(v_i)}
=
d_i^{\mathrm{old},(v_i+1)}
\label{eq:history-continuity}
\end{equation}$$ thereby binding each redaction output to the next input
state.

**Step 2: Transaction-Specific Index Update**

After updating the history, the PAI computes $$\begin{equation}
A_i^{(v_i+1)}
=
H\left(
TID_i\parallel(v_i+1)\parallel c_i^{(v_i+1)}
\right)
\label{eq:pai-entry}
\end{equation}$$ The key $TID_i$ provides direct access to
$\mathcal{H}_i$, while the version and cumulative commitment bind its
expected length, ordering, and terminal history state.

**Step 3: PAI Authentication**

After all successful records of round $e$ are incorporated, the PAI
computes $$\begin{equation}
R_{\mathrm{PAI}}^{(e)}
=
\mathsf{MerkleRoot}
\left(
\left\{
A_i^{(v_i)}
\right\}_{i\in\mathcal{I}^{(e)}}
\right)
\label{eq:pai-update-root}
\end{equation}$$ where $\mathcal{I}^{(e)}$ is the set of indexed
transactions and $v_i$ denotes each transaction's latest version after
round $e$. A target entry admits the authentication path
$$\begin{equation}
\mu_i^{(e)}
=
\mathsf{MerkleProof}
\left(
A_i^{(v_i)},R_{\mathrm{PAI}}^{(e)}
\right)
\label{eq:pai-proof}
\end{equation}$$

**Step 4: Blockchain Anchoring**

After each completed redaction round $e$, ZK-Redact computes
$$\begin{equation}
AC^{(e)}
=
H\left(
e\parallel R_{\mathrm{PAI}}^{(e)}
\parallel R_{\mathrm{PAI}}^{(e-1)}
\parallel C_B^{(e)}
\right)
\label{eq:pai-anchor}
\end{equation}$$ and constructs $$\begin{equation}
AR^{(e)}
=
\left(
e,R_{\mathrm{PAI}}^{(e)},R_{\mathrm{PAI}}^{(e-1)},
C_B^{(e)},AC^{(e)}
\right)
\label{eq:pai-anchor-record}
\end{equation}$$ The permissioned blockchain records $AR^{(e)}$ as the
trusted provenance anchor. This jointly binds the updated PAI state, its
predecessor, and the successful batch-result commitment $C_B^{(e)}$ to
redaction round $e$, enabling independent anchor verification in
Phase 6.

Phase 5 therefore maintains hash-linked, transaction-specific provenance
and authenticates each completed redaction round through a
blockchain-anchored PAI root. The authenticated version and terminal
commitment enable Phase 6 to detect missing, modified, reordered, or
truncated provenance records without scanning unrelated blockchain
history.

### **Phase 6: Provenance Retrieval and Audit Verification** {#sec:phase6 .unnumbered}

This phase enables an authorized auditor to retrieve and independently
verify a transaction's redaction history without scanning unrelated
blockchain records.

**Step 1: Auditor Authentication and Query Authorization**

Before retrieving provenance, auditor $AU_a$ constructs
$$\begin{equation}
R_a^{\mathrm{audit}}
=
(AID_a,TID_i,e,t_a,\nu_a)
\label{eq:auditor-request}
\end{equation}$$ where $AID_a$ is the registered auditor identifier, $e$
is the target PAI state, and $(t_a,\nu_a)$ provides freshness. The
auditor signs $$\begin{equation}
\sigma_a=
\mathsf{Sig.Sign}
\left(
sk_a,H(R_a^{\mathrm{audit}})
\right)
\label{eq:auditor-signature}
\end{equation}$$

Upon receiving $(R_a^{\mathrm{audit}},\sigma_a)$, the permissioned
blockchain verifies $$\begin{equation}
\mathsf{Sig.Verify}
\left(
pk_a,H(R_a^{\mathrm{audit}}),\sigma_a
\right)=1
\label{eq:auditor-authentication}
\end{equation}$$ using the registered public key $pk_a$, and checks the
freshness of $(t_a,\nu_a)$. The audit-access chaincode then evaluates
$$\begin{equation}
\mathsf{AuditAuth}
(AID_a,TID_i,e,\mathcal{P}_a^{\mathrm{audit}})=1
\label{eq:auditor-authorization}
\end{equation}$$ where $\mathcal{P}_a^{\mathrm{audit}}$ is the
registered audit policy of $AU_a$. The query proceeds only if the
signature, freshness, and audit-authorization checks are valid;
otherwise, it is rejected before provenance retrieval.

**Step 2: Provenance and Audit-Evidence Retrieval**

Once authenticated, for target $TID_i$ and PAI state $e$, the auditor
submits the retrieval query $$\begin{equation}
Q_i^{\mathrm{audit}}=(TID_i,e)
\end{equation}$$ The PAI returns $$\begin{equation}
\mathcal{E}_i^{(e)}
=
\left(
\mathcal{H}_i^{(v_i)},v_i,c_i^{(v_i)},
A_i^{(v_i)},\mu_i^{(e)}
\right)
\end{equation}$$ where $\mathcal{H}_i^{(v_i)}$ is the ordered provenance
history and $\mu_i^{(e)}$ its Merkle authentication path. Using the
$DID$ in each record, the auditor retrieves the corresponding public
evidence $(x_{i,k},\pi_{i,k})$ from the off-chain audit-evidence store.

From the permissioned blockchain, the auditor independently obtains the
authenticated initial and epoch-$e$ transaction states and the anchor
record $$\begin{equation}
AR^{(e)}
=
\left(
e,R_{\mathrm{PAI}}^{(e)},R_{\mathrm{PAI}}^{(e-1)},
C_B^{(e)},AC^{(e)}
\right)
\label{eq:audit-anchor-record}
\end{equation}$$

**Step 3: PAI and History Verification**

The auditor recomputes $$\begin{equation}
\widehat{A}_i^{(v_i)}
=
H(TID_i\parallel v_i\parallel c_i^{(v_i)})
\label{eq:audit-entry}
\end{equation}$$ and verifies $$\begin{equation}
\mathsf{MerkleVerify}
\left(
\widehat{A}_i^{(v_i)},\mu_i^{(e)},
R_{\mathrm{PAI}}^{(e)}
\right)=1
\label{eq:audit-merkle}
\end{equation}$$

Starting from authenticated $T_i^{(0)}$, it reconstructs
$$\begin{equation}
\widehat{c}_i^{(0)}
=
H(TID_i\parallel0\parallel H(T_i^{(0)}))
\label{eq:audit-initial}
\end{equation}$$ and, for $1\leq k\leq v_i$, $$\begin{equation}
\widehat{c}_i^{(k)}
=
H\left(
\widehat{c}_i^{(k-1)}
\parallel H(PR_i^{(k)})
\right)
\label{eq:audit-chain}
\end{equation}$$ History integrity and completeness require
$$\begin{equation}
|\mathcal{H}_i^{(v_i)}|=v_i,
\qquad
\widehat{c}_i^{(v_i)}=c_i^{(v_i)}
\label{eq:audit-completeness}
\end{equation}$$ Thus, missing, inserted, modified, reordered, or
truncated records cannot match the authenticated PAI entry.

**Step 4: Authorization and State-Continuity Verification**

For each $PR_i^{(k)}$, the auditor computes $$\begin{equation}
\eta_{i,k}=H(x_{i,k})
\end{equation}$$ $$\begin{equation}
\widehat{C}_{i,k}^{\mathrm{auth}}
=
H(DID_{i,k}\parallel\eta_{i,k}\parallel H(\pi_{i,k}))
\label{eq:audit-auth}
\end{equation}$$ and accepts its authorization only if
$$\begin{equation}
\widehat{C}_{i,k}^{\mathrm{auth}}
=
C_{i,k}^{\mathrm{auth}}
\quad\land\quad
\mathsf{ZK.Verify}
(vk_{\mathrm{zk}},x_{i,k},\pi_{i,k})=1
\label{eq:audit-authorization}
\end{equation}$$ The auditor also checks the transaction and policy
versions recorded in $PR_i^{(k)}$.

For successive redactions, the auditor verifies $$\begin{equation}
d_i^{\mathrm{new},(k)}
=
d_i^{\mathrm{old},(k+1)},
\qquad 1\leq k<v_i
\label{eq:audit-state-continuity}
\end{equation}$$ and $$\begin{equation}
v_i^{(k+1)}
=
v_i^{(k)}+1,
\qquad 1\leq k<v_i
\label{eq:audit-version-continuity}
\end{equation}$$ It further verifies the boundary states as
$$\begin{equation}
d_i^{\mathrm{old},(1)}
=
H(T_i^{(0)})
\end{equation}$$ $$\begin{equation}
d_i^{\mathrm{new},(v_i)}
=
H(T_i^{(v_i,e)})
\label{eq:audit-boundary-states}
\end{equation}$$ where $T_i^{(0)}$ is the authenticated initial state
and $T_i^{(v_i,e)}$ is the authenticated transaction state associated
with the audited PAI state $e$.

**Step 5: Anchor Verification**

Finally, the auditor verifies $$\begin{equation}
AC^{(e)}
\stackrel{?}{=}
H\left(
e\parallel R_{\mathrm{PAI}}^{(e)}
\parallel R_{\mathrm{PAI}}^{(e-1)}
\parallel C_B^{(e)}
\right)
\label{eq:audit-anchor}
\end{equation}$$ This binds the authenticated PAI state to its
predecessor and the successful batch-result commitment of redaction
round $e$.

The audit succeeds only if the PAI membership, provenance commitment,
ZKP authorization, state continuity, and blockchain anchor are valid.
Thus, ZK-Redact supports transaction-specific verification of redaction
authorization, history integrity, completeness, and continuity without
exhaustive blockchain traversal.

::: thebibliography
99

M. Jia, J. Chen, K. He, R. Du, L. Zheng, M. Lai, D. Wang, and F. Liu,
"Redactable Blockchain from Decentralized Chameleon Hash Functions,"
*IEEE Trans. Inf. Forensics Security*, vol. 17, pp. 2771--2783, 2022,
doi: 10.1109/TIFS.2022.3192716.

K. Huang, X. Zhang, Y. Mu, X. Wang, G. Yang, X. Du, F. Rezaeibagha, Q.
Xia, and M. Guizani, "Building Redactable Consortium Blockchain for
Industrial Internet-of-Things," *IEEE Trans. Ind. Informat.*, vol. 15,
no. 6, pp. 3670--3679, Jun. 2019, doi: 10.1109/TII.2019.2901011.

W. Wang, L. Wang, J. Duan, X. Tong, and H. Peng, "Redactable Blockchain
Based on Decentralized Trapdoor Verifiable Delay Functions," *IEEE
Trans. Inf. Forensics Security*, vol. 19, pp. 7492--7507, 2024, doi:
10.1109/TIFS.2024.3431917.

H. Guo, W. Gan, M. Zhao, C. Zhang, T. Wu, L. Zhu, and J. Xue, "PriChain:
Efficient Privacy-Preserving Fine-Grained Redactable Blockchains in
Decentralized Settings," *Chinese Journal of Electronics*, vol. 34, no.
1, pp. 82--97, 2025, doi: 10.23919/cje.2023.00.305.

D. Zhang, J. Le, X. Lei, T. Xiang, and X. Liao, "Secure Redactable
Blockchain With Dynamic Support," *IEEE Trans. Dependable Secure
Comput.*, vol. 21, no. 2, pp. 717--731, 2024, doi:
10.1109/TDSC.2023.3261343.

X. Wu, X. Du, Q. Yang, N. Wang, and W. Wang, "Redactable consortium
blockchain based on verifiable distributed chameleon hash functions,"
*J. Parallel Distrib. Comput.*, vol. 183, Art. no. 104777, 2024, doi:
10.1016/j.jpdc.2023.104777.

S. Aguincha, E. Nunes, S. Eisa, and M. L. Pardal, "ChainGuards:
Verification of Sensed Data using Permissioned Blockchain Technology,"
arXiv preprint arXiv:2603.20769, 2026.

D. Derler, K. Samelin, D. Slamanig, and C. Striecks, "Fine-Grained and
Controlled Rewriting in Blockchains: Chameleon-Hashing Gone
Attribute-Based," in *Proc. 26th Annu. Netw. Distrib. Syst. Security
Symp. (NDSS)*, 2019, doi: 10.14722/ndss.2019.23066.

G. Ateniese, B. Magri, D. Venturi, and E. R. Andrade, "Redactable
Blockchain -- or -- Rewriting History in Bitcoin and Friends," in *Proc.
2nd IEEE Eur. Symp. Security Privacy (EuroS&P)*, Paris, France, pp.
111--126, 2017, doi: 10.1109/EuroSP.2017.37.

Z. Wu, L. Wang, X. Zhang and X. Feng, \"EMT: Extended Merkle Tree
Structure for Inserted Data Redaction in Permissioned Blockchain,\" in
IEEE Transactions on Network Science and Engineering, vol. 12, no. 4,
pp. 3025-3038, July-Aug. 2025, doi: 10.1109/TNSE.2025.3555979.

T. Sengupta, S. Chakraborty and S. Sural, \"ReAcct: Redaction Control
for Interoperable Blockchains,\" 2025 7th Conference on Blockchain
Research & Applications for Innovative Networks and Services (BRAINS),
Zurich, Switzerland, 2025, pp. 1-10, doi:
10.1109/BRAINS67003.2025.11302947.

K. Y. Chan, L. Chen, Y. Tian, and T. H. Yuen, "Reconstructing Chameleon
Hash: Full Security and the Multi-Party Setting," in *Proc. 19th ACM
Asia Conf. Computer and Communications Security (AsiaCCS)*, pp.
1076--1091, 2024, doi: 10.1145/3634737.3656291.

G. Tian, J. Wei, M. Kutylowski, W. Susilo, X. Huang, and X. Chen, "VRBC:
A Verifiable Redactable Blockchain with Efficient Query and Integrity
Auditing," *IEEE Trans. Comput.*, vol. 72, no. 7, pp. 1928--1942, Jul.
2023, doi: 10.1109/TC.2022.3230900.

K. Huang, X. Zhang, Y. Mu, F. Rezaeibagha, and X. Du, "Scalable and
redactable blockchain with update and anonymity," *Information
Sciences*, vol. 546, pp. 25--41, 2021, doi: 10.1016/j.ins.2020.07.016.

Y. Dong, Y. Li, Y. Cheng, and D. Yu, "Redactable consortium blockchain
with access control: Leveraging chameleon hash and multi-authority
attribute-based encryption," *High-Confidence Computing*, vol. 4, no. 1,
Art. no. 100168, 2024, doi: 10.1016/j.hcc.2023.100168.

Y. Zhang, Z. Ma, S. Luo, and P. Duan, "Dynamic Trust-Based Redactable
Blockchain Supporting Update and Traceability," *IEEE Trans. Inf.
Forensics Security*, vol. 19, pp. 821--834, 2024, doi:
10.1109/TIFS.2023.3326379.

F. Wang, R. Dong, J. Cui, Q. Zhang and H. Zhong, \"Blockchain-Based
Anonymous and Accountable Data Redaction for the Industrial Internet of
Things,\" in IEEE Transactions on Cloud Computing, doi:
10.1109/TCC.2026.3725253.

J. B. Klamti and M. A. Hasan, "Revocable policy-based chameleon hash
using lattices," *Journal of Mathematical Cryptology*, vol. 18, no. 1,
Art. no. 20230012, pp. 152--182, 2024, doi: 10.1515/jmc-2023-0012.

X. Huang, Y. Wang, Y. Ding, Q. Wu, C. Yang, and H. Liang, "Dynamically
redactable Blockchain based on decentralized Chameleon hash," *Digital
Communications and Networks*, vol. 11, no. 3, pp. 757--767, 2025, doi:
10.1016/j.dcan.2024.10.013.

M. Miao, X. Yang, J. Wei, G. Tian, and W. Susilo, "A Verifiable and
Redactable Blockchain with Lightweight Storage and Permission
Supervision," *Information*, vol. 17, no. 2, Art. no. 176, 2026, doi:
10.3390/info17020176.

S. Fugkeaw, S. Sungchai, S. Nakprame, and P. Sreekongpan, "Enabling
Secure and Scalable GDPR-Compliant Blockchain-Based e-KYC With Efficient
Redaction," *IEEE Access*, vol. 13, pp. 136834--136853, 2025, doi:
10.1109/ACCESS.2025.3594656.
:::
