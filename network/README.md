# Fabric network

The permissioned network the evaluation runs against, and the redaction
chaincode deployed to it.

## Why this exists

Ref[10]'s authorization is a committee vote. Its cost is dominated by ballots
crossing the network and reaching consensus — that is the whole difference
between a committee protocol and the single key-possession check Ref[13] and
Ref[22] perform, and Exp 1 exists to measure how that difference behaves under
concurrent load.

`vote_transport: in_process` runs the same cryptography by function call. Its
numbers are a **lower bound** with the dominant term removed. This directory is
what turns them into Ref[10]'s actual cost.

## Two topologies

| | `compose.minimal.yaml` | `compose.yaml` |
|---|---|---|
| Purpose | verify the mechanism | produce measurements |
| Orgs × peers | 1 × 1 | 4 × 2 |
| Orderers | 1 (solo-style Raft) | 3 (Raft) |
| RAM | ~1.5 GB | ~5 GB |
| Runs on | a developer laptop | the c6i.8xlarge target |

**Only `compose.yaml` may produce results.** The minimal topology has one
endorser and one orderer, so it does not exercise endorsement across
organisations or Raft leader election — the costs Exp 1 is measuring. It exists
so that "does the chaincode deploy, does the SDK connect, do votes actually go
through ordering" can be answered without a 32-vCPU host.

`scripts/network.sh` refuses to record a run against the minimal topology for
exactly that reason.

## Dependencies beyond the base toolchain

Per `SKILL.md`, anything outside the declared toolchain is recorded here.

| Dependency | Purpose | Notes |
|---|---|---|
| Hyperledger Fabric 2.5.9 binaries | `peer`, `configtxgen`, `cryptogen` | installed by `scripts/setup-ec2.sh` |
| Fabric Docker images 2.5.9 | peer, orderer, CA, ccenv | ~2 GB pull on first use |
| `github.com/hyperledger/fabric-gateway` | client SDK, main module | **new main-module dependency** |
| `github.com/hyperledger/fabric-contract-api-go` | chaincode | confined to `chaincode/redaction`, which is a separate Go module |

The chaincode is a **separate Go module** on purpose: its dependency tree is
large, and Fabric packages chaincode independently. Keeping it out of the main
module means `go build ./...` for the harness stays fast and its `go.sum` stays
small.

## Layout

```
network/
├── chaincode/redaction/     Algorithm 3 as chaincode (own Go module)
├── compose.minimal.yaml     1 org, verification only
├── compose.yaml             4 orgs, measurement topology
├── configtx.yaml            channel and ordering configuration
├── crypto-config.yaml       identity material to generate
└── scripts/
    ├── network.sh           up | down | deploy | status
    └── smoke.sh             end-to-end check against a live network
```

## Usage

```bash
# Verify the mechanism (laptop)
./scripts/network.sh up minimal
./scripts/network.sh deploy
./scripts/smoke.sh

# Measurement topology (EC2)
./scripts/network.sh up full
./scripts/network.sh deploy
make experiment-verification-throughput
```

## What the chaincode does not trust

The contract recomputes the committee from the registered node set, verifies
every ballot signature itself, and enforces one ballot per member. None of that
is redundant with the client: a client that could name its own committee, or
submit ballots on behalf of members that never voted, would make the threshold
meaningless — and the measured protocol would be one nobody would deploy.

Because the chaincode is a separate module it cannot import `pkg/crypto`, so
its Schnorr verification is a second implementation of the same equations.
`TestChaincodeVerifiesPkgCryptoSignatures` pins the two together against golden
vectors. That test exists because the first draft had the sign inverted, which
would have rejected every honest vote and presented as a network that never
reached threshold.
