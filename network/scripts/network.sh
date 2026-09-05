#!/usr/bin/env bash
#
# Bring the Fabric network up or down, and deploy the redaction chaincode.
#
#   ./network.sh up minimal     one org, one peer — VERIFICATION ONLY
#   ./network.sh up full        measurement topology
#   ./network.sh deploy         package, install and commit the chaincode
#   ./network.sh status
#   ./network.sh down           stop and remove everything, including volumes
#
# TOPOLOGY MARKER. `up minimal` writes .topology recording which one is
# running. The harness reads it and refuses to record results against the
# minimal topology, which has one endorser and one orderer and therefore lacks
# the cross-organisation endorsement and Raft replication Exp 1 measures. A
# number taken there would understate Ref[10] the same way the in-process
# transport does, only less visibly.

set -euo pipefail

NET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$NET_DIR/.." && pwd)"

CHANNEL="${CHANNEL:-redaction}"
CC_NAME="${CC_NAME:-redaction}"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
FABRIC_BIN="${FABRIC_BIN:-/c/fabric/bin}"

MARKER="$NET_DIR/.topology"

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLD=$'\e[1m'; RST=$'\e[0m'
step() { printf '\n%s==> %s%s\n' "$BLD" "$1" "$RST"; }
ok()   { printf '%s  ok%s   %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s  warn%s %s\n' "$YLW" "$RST" "$1"; }
die()  { printf '%s  fail%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }

export PATH="$FABRIC_BIN:$PATH"

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 not found. Set FABRIC_BIN, or run scripts/setup-ec2.sh"
}

# -----------------------------------------------------------------------------
# Config agreement
#
# The channel's batch settings ARE part of what Exp 1 measures: a submitted vote
# waits up to BatchTimeout before ordering. If the channel batches on a
# different timeout than config/experiment.yaml records, the measured latency
# cannot be traced to any recorded parameter.
# -----------------------------------------------------------------------------
check_config_agreement() {
  local cfg="$REPO_ROOT/config/experiment.yaml"
  [[ -r "$cfg" ]] || { warn "cannot read $cfg; skipping batch-parameter check"; return 0; }

  local cfg_timeout cfg_max ctx_timeout ctx_max
  cfg_timeout=$(grep -E '^\s*block_timeout_ms:' "$cfg" | head -1 | grep -oE '[0-9]+' || true)
  cfg_max=$(grep -E '^\s*block_max_transactions:' "$cfg" | head -1 | grep -oE '[0-9]+' || true)
  ctx_timeout=$(grep -E '^\s*BatchTimeout:' "$NET_DIR/configtx.yaml" | head -1 | grep -oE '[0-9]+' || true)
  ctx_max=$(grep -E '^\s*MaxMessageCount:' "$NET_DIR/configtx.yaml" | head -1 | grep -oE '[0-9]+' || true)

  [[ -n "$cfg_timeout" && -n "$ctx_timeout" ]] || { warn "batch parameters not found in both files"; return 0; }

  # configtx BatchTimeout is in seconds, the config is in milliseconds.
  if (( ctx_timeout * 1000 != cfg_timeout )); then
    die "channel BatchTimeout is ${ctx_timeout}s but config/experiment.yaml has block_timeout_ms=${cfg_timeout}.
       A vote waits up to this long before ordering, so it is part of Exp 1's
       measurement. Make them agree before bringing the network up."
  fi
  if [[ -n "$cfg_max" && -n "$ctx_max" ]] && (( ctx_max != cfg_max )); then
    die "channel MaxMessageCount is $ctx_max but config has block_max_transactions=$cfg_max"
  fi
  ok "channel batch parameters agree with config/experiment.yaml"
}

# -----------------------------------------------------------------------------
# Crypto material
# -----------------------------------------------------------------------------
generate_crypto() {
  local topology="$1"
  step "Generating identity material ($topology)"

  need cryptogen
  rm -rf "$NET_DIR/organizations"

  local spec="$NET_DIR/crypto-config-$topology.yaml"
  [[ -r "$spec" ]] || die "missing $spec"

  ( cd "$NET_DIR" && cryptogen generate --config="$spec" --output=organizations ) \
    || die "cryptogen failed"

  local users
  users=$(find "$NET_DIR/organizations/peerOrganizations" -type d -name 'User*' 2>/dev/null | wc -l)
  ok "generated material for $users voting identities"

  # The committee cannot be formed from fewer identities than it needs, and the
  # failure would surface at vote time as a missing-identity error rather than
  # as a setup problem.
  local committee
  committee=$(grep -E '^\s*committee_size:' "$REPO_ROOT/config/experiment.yaml" | head -1 | grep -oE '[0-9]+' || true)
  if [[ -n "$committee" ]] && (( users < committee )); then
    die "config requires committee_size=$committee but only $users voting identities exist.
       Raise Users.Count in $spec."
  fi
}

# -----------------------------------------------------------------------------
# Channel
# -----------------------------------------------------------------------------
create_channel() {
  local topology="$1"
  step "Creating channel $CHANNEL ($topology)"
  need configtxgen
  need osnadmin

  # The profile MUST follow the topology. A full network created from the
  # minimal profile comes up with eight peers but a single-organisation
  # channel: the other orgs can never join, endorsement never crosses an
  # organisational boundary, and the run looks like a measurement while being
  # one org wide.
  local profile="MinimalChannel" orderers=1
  if [[ "$topology" == "full" ]]; then
    profile="FullChannel"
    orderers=3
  fi

  mkdir -p "$NET_DIR/channel-artifacts"
  ( cd "$NET_DIR" && FABRIC_CFG_PATH="$NET_DIR" configtxgen       -profile "$profile" -outputBlock "channel-artifacts/$CHANNEL.block" -channelID "$CHANNEL" )     || die "configtxgen failed"
  ok "genesis block from profile $profile"

  # Every orderer joins, not just the first: a Raft set with one member has no
  # leader election and no follower replication, which are part of the commit
  # latency Exp 1 measures.
  for ((i = 0; i < orderers; i++)); do
    local tls="$NET_DIR/organizations/ordererOrganizations/example.com/orderers/orderer$i.example.com/tls"
    local admin_port=$((7053 + i * 1000))
    osnadmin channel join       --channelID "$CHANNEL"       --config-block "$NET_DIR/channel-artifacts/$CHANNEL.block"       -o "localhost:$admin_port"       --ca-file "$tls/ca.crt"       --client-cert "$tls/server.crt"       --client-key "$tls/server.key" >/dev/null       || die "orderer$i failed to join the channel"
  done
  ok "$orderers orderer(s) joined"

  # Every peer joins. A peer outside the channel cannot endorse, so leaving one
  # out quietly shrinks the endorsement set the policy is evaluated against.
  local orgs=1 peers=1
  if [[ "$topology" == "full" ]]; then
    orgs=4; peers=2
  fi
  local joined=0
  for ((o = 1; o <= orgs; o++)); do
    for ((pnum = 0; pnum < peers; pnum++)); do
      peer_env "$o" "$pnum" "$topology"
      peer channel join -b "$NET_DIR/channel-artifacts/$CHANNEL.block" >/dev/null         || die "peer$pnum.org$o failed to join the channel"
      joined=$((joined + 1))
    done
  done
  ok "$joined peer(s) joined"
}

# peer_env points the CLI at one peer.
#
# Ports follow compose: the minimal topology exposes peer0.org1 on 7051; the
# full topology exposes peer<n>.org<o> on 11051 + 1000*(2*(o-1) + n).
peer_env() {
  local org="${1:-1}" pnum="${2:-0}" topology="${3:-minimal}"
  local dir="$NET_DIR/organizations/peerOrganizations/org$org.example.com"

  export FABRIC_CFG_PATH="$FABRIC_BIN/../config"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org${org}MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="$dir/peers/peer$pnum.org$org.example.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="$dir/users/Admin@org$org.example.com/msp"

  if [[ "$topology" == "full" ]]; then
    export CORE_PEER_ADDRESS="localhost:$((11051 + 1000 * (2 * (org - 1) + pnum)))"
  else
    export CORE_PEER_ADDRESS=localhost:7051
  fi
}

# -----------------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------------
cmd_up() {
  local topology="${1:-}"
  [[ "$topology" == "minimal" || "$topology" == "full" ]] \
    || die "usage: network.sh up [minimal|full]"

  docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"

  local compose="$NET_DIR/compose.yaml"
  [[ "$topology" == "minimal" ]] && compose="$NET_DIR/compose.minimal.yaml"
  [[ -r "$compose" ]] || die "missing $compose"

  check_config_agreement

  # Tear down first. generate_crypto issues a NEW CA, and `docker compose up -d`
  # leaves already-running containers alone — so a second `up` gives clients
  # certificates from the new CA while the orderers still trust the old one.
  # The failure is "certificate signed by unknown authority", which reads as a
  # TLS misconfiguration rather than as stale containers.
  step "Clearing any previous network"
  cmd_down_quiet

  generate_crypto "$topology"

  step "Starting containers ($topology)"
  docker compose -f "$compose" up -d || die "docker compose failed"

  # Peers report ready before their gRPC listener accepts connections; joining
  # too early fails with a connection error that looks like a misconfiguration.
  local waited=0
  until docker compose -f "$compose" ps --format '{{.State}}' | grep -q running; do
    sleep 1; waited=$((waited+1))
    (( waited < 60 )) || die "containers did not reach running state"
  done
  sleep 3
  ok "containers running"

  create_channel "$topology"

  echo "$topology" > "$MARKER"
  if [[ "$topology" == "minimal" ]]; then
    warn "MINIMAL topology is up — verification only."
    warn "One endorser and one orderer: no cross-org endorsement, no Raft replication."
    warn "The harness will refuse to record results while this marker exists."
  fi
  ok "network up ($topology)"
}

cmd_deploy() {
  step "Deploying chaincode $CC_NAME (chaincode-as-a-service)"
  need peer
  [[ -f "$MARKER" ]] || die "no network is up; run network.sh up first"

  local cc_src="$NET_DIR/chaincode/redaction"
  [[ -d "$cc_src" ]] || die "missing $cc_src"

  ( cd "$cc_src" && go mod vendor ) || die "go mod vendor failed in $cc_src"
  ok "vendored chaincode dependencies"

  # The builder image must satisfy the module's go directive. When they drift,
  # the failure is a build error inside a container that reads as a Docker
  # problem rather than a version mismatch.
  local mod_go img_go
  mod_go=$(grep -E '^go ' "$cc_src/go.mod" | awk '{print $2}' | cut -d. -f1,2)
  img_go=$(grep -oE 'FROM golang:[0-9]+\.[0-9]+' "$cc_src/Dockerfile" | head -1 | cut -d: -f2)
  if [[ -n "$mod_go" && -n "$img_go" && "$mod_go" != "$img_go" ]]; then
    die "chaincode go.mod requires Go $mod_go but its Dockerfile builds with $img_go.
       Update FROM golang:$mod_go-alpine in $cc_src/Dockerfile."
  fi
  ok "builder image Go $img_go satisfies go.mod"

  # Package as ccaas rather than golang.
  #
  # The golang package type makes the peer build a container image over the
  # Docker socket, which fails under Docker Desktop on Windows: the proxy closes
  # the connection mid-build and the peer reports "broken pipe" rather than
  # anything about the chaincode. Running the contract as its own service skips
  # the peer's build step entirely, and is what production deployments use.
  # Layout matters and is easy to get wrong: connection.json sits at the ROOT of
  # code.tar.gz, and the peer extracts that archive INTO src/. Packaging it as
  # src/connection.json produces src/src/connection.json after extraction, and
  # the builder reports the file as missing without saying where it looked.
  local pkgdir="$NET_DIR/channel-artifacts/ccaas"
  rm -rf "$pkgdir"; mkdir -p "$pkgdir"

  cat > "$pkgdir/connection.json" <<JSON
{
  "address": "redaction-cc:9999",
  "dial_timeout": "10s",
  "tls_required": false
}
JSON
  cat > "$pkgdir/metadata.json" <<JSON
{
  "type": "ccaas",
  "label": "${CC_NAME}_${CC_VERSION}"
}
JSON

  ( cd "$pkgdir" && tar -czf code.tar.gz connection.json       && tar -czf "$NET_DIR/channel-artifacts/${CC_NAME}.tar.gz" metadata.json code.tar.gz )     || die "packaging failed"
  ok "packaged as ccaas"

  local topology; topology=$(cat "$MARKER")
  local orgs=1 peers=1
  if [[ "$topology" == "full" ]]; then
    orgs=4; peers=2
  fi

  local pkg="$NET_DIR/channel-artifacts/${CC_NAME}.tar.gz"
  local pkg_id
  pkg_id=$(peer_env 1 0 "$topology"; peer lifecycle chaincode calculatepackageid "$pkg" 2>/dev/null)
  [[ -n "$pkg_id" ]] || die "could not compute the package id"
  ok "package id $pkg_id"

  # Install on every peer. A peer without the chaincode cannot endorse, so
  # leaving one out shrinks the endorsement set the MAJORITY policy is
  # evaluated against — silently, since the remaining peers still succeed.
  local installed=0
  for ((o = 1; o <= orgs; o++)); do
    for ((pnum = 0; pnum < peers; pnum++)); do
      peer_env "$o" "$pnum" "$topology"
      peer lifecycle chaincode install "$pkg" >/dev/null 2>&1         || die "install on peer$pnum.org$o failed; run it without redirection to see the builder error"
      installed=$((installed + 1))
    done
  done
  ok "installed on $installed peer(s)"

  # The chaincode service must be running before the definition is committed:
  # the peer connects to it to initialise, and a missing service surfaces as a
  # commit timeout rather than as an absent container.
  step "Starting the chaincode service"
  CHAINCODE_ID="$pkg_id" docker compose -f "$NET_DIR/chaincode-service.yaml" up -d --build     || die "failed to start the chaincode service"

  local waited=0
  until docker ps --filter "name=redaction-cc" --format '{{.State}}' | grep -q running; do
    sleep 1; waited=$((waited+1))
    (( waited < 120 )) || die "chaincode service did not start"
  done
  ok "chaincode service running"

  step "Approving and committing"
  local tls="$NET_DIR/organizations/ordererOrganizations/example.com/orderers/orderer0.example.com/tls/ca.crt"

  # Every org approves. The lifecycle policy is MAJORITY, so a commit with only
  # one org's approval fails — and with all four the commit itself exercises
  # cross-organisation endorsement, which is what the full topology is for.
  for ((o = 1; o <= orgs; o++)); do
    peer_env "$o" 0 "$topology"
    peer lifecycle chaincode approveformyorg       -o localhost:7050 --ordererTLSHostnameOverride orderer0.example.com       --tls --cafile "$tls" --channelID "$CHANNEL"       --name "$CC_NAME" --version "$CC_VERSION" --package-id "$pkg_id"       --sequence "$CC_SEQUENCE" >/dev/null || die "approve failed for org$o"
  done
  ok "$orgs org(s) approved"

  # Commit names one peer per org so endorsement is collected across all of
  # them, as the policy requires.
  local peer_args=()
  for ((o = 1; o <= orgs; o++)); do
    local addr
    if [[ "$topology" == "full" ]]; then
      addr="localhost:$((11051 + 1000 * (2 * (o - 1))))"
    else
      addr="localhost:7051"
    fi
    peer_args+=(--peerAddresses "$addr" --tlsRootCertFiles
      "$NET_DIR/organizations/peerOrganizations/org$o.example.com/peers/peer0.org$o.example.com/tls/ca.crt")
  done

  peer_env 1 0 "$topology"
  peer lifecycle chaincode commit     -o localhost:7050 --ordererTLSHostnameOverride orderer0.example.com     --tls --cafile "$tls" --channelID "$CHANNEL"     --name "$CC_NAME" --version "$CC_VERSION" --sequence "$CC_SEQUENCE"     "${peer_args[@]}" >/dev/null || die "commit failed"
  ok "committed to channel $CHANNEL"
}

cmd_status() {
  step "Status"
  if [[ -f "$MARKER" ]]; then
    local t; t=$(cat "$MARKER")
    printf '     topology: %s\n' "$t"
    [[ "$t" == "minimal" ]] && warn "verification only — not valid for results"
  else
    printf '     topology: none recorded\n'
  fi
  docker ps --filter "network=zkredact_fabric" \
    --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null || true
}

# cmd_down_quiet is cmd_down without the banner, for reuse from cmd_up.
cmd_down_quiet() {
  CHAINCODE_ID=unused docker compose -f "$NET_DIR/chaincode-service.yaml" down -v --remove-orphans 2>/dev/null || true
  for c in "$NET_DIR/compose.yaml" "$NET_DIR/compose.minimal.yaml"; do
    [[ -r "$c" ]] && docker compose -f "$c" down -v --remove-orphans 2>/dev/null || true
  done
  docker ps -aq --filter "name=dev-peer" | xargs -r docker rm -f >/dev/null 2>&1 || true
  rm -f "$MARKER"
  rm -rf "$NET_DIR/organizations" "$NET_DIR/channel-artifacts"
}

cmd_down() {
  step "Tearing down"
  CHAINCODE_ID=unused docker compose -f "$NET_DIR/chaincode-service.yaml" down -v --remove-orphans 2>/dev/null || true
  for c in "$NET_DIR/compose.yaml" "$NET_DIR/compose.minimal.yaml"; do
    [[ -r "$c" ]] && docker compose -f "$c" down -v --remove-orphans 2>/dev/null || true
  done
  # Chaincode containers are created by the peer, not by compose.
  docker ps -aq --filter "name=dev-peer" | xargs -r docker rm -f >/dev/null 2>&1 || true
  rm -f "$MARKER"
  rm -rf "$NET_DIR/organizations" "$NET_DIR/channel-artifacts"
  ok "down"
}

case "${1:-}" in
  up)     shift; cmd_up "$@" ;;
  deploy) cmd_deploy ;;
  status) cmd_status ;;
  down)   cmd_down ;;
  *)      echo "usage: network.sh {up [minimal|full]|deploy|status|down}" >&2; exit 2 ;;
esac
