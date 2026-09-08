#!/usr/bin/env bash
#
# Provision an Ubuntu 22.04 EC2 instance for the ZK-Redact evaluation.
#
#   ./scripts/setup-ec2.sh          install everything
#   ./scripts/setup-ec2.sh verify   check an existing install, change nothing
#
# Idempotent: re-running skips anything already present at the right version.
#
# Target (SKILL.md): c6i.8xlarge, 32 vCPU, 64 GB, 200 GB gp3.
# Go only — gnark-crypto covers both Groth16 and the BLS12-381 pairings the
# Ref[13] baseline needs, so there is no Rust or Node.js toolchain here.

set -euo pipefail

GO_MIN_MINOR=21            # SKILL.md requires Go >= 1.21
PROTOC_MIN=3.21
FABRIC_VERSION=2.5.9
FABRIC_CA_VERSION=1.5.12

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLD=$'\e[1m'; RST=$'\e[0m'

step() { printf '\n%s==> %s%s\n' "$BLD" "$1" "$RST"; }
ok()   { printf '%s  ok%s   %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s  warn%s %s\n' "$YLW" "$RST" "$1"; }
die()  { printf '%s  fail%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }

MODE="${1:-install}"
[[ "$MODE" == "install" || "$MODE" == "verify" ]] || die "usage: $0 [install|verify]"

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------
step "Preflight"

[[ "$(uname -s)" == "Linux" ]] || die "this script targets Linux (Ubuntu 22.04)"

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
        warn "expected Ubuntu, found ${PRETTY_NAME:-unknown} — continuing anyway"
    elif [[ "${VERSION_ID:-}" != "22.04" ]]; then
        warn "expected Ubuntu 22.04, found ${VERSION_ID:-unknown}"
    else
        ok "Ubuntu 22.04"
    fi
fi

CPUS=$(nproc)
MEM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
DISK_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')

printf '     %s vCPU, %s GB RAM, %s GB free disk\n' "$CPUS" "$MEM_GB" "$DISK_GB"

# The config's CPU budget: peers+orderers+loadgen take ~12, leaving ~20 for the
# system under test. Below 32 the Exp 1 saturation point becomes an artefact of
# contention rather than a property of sharding.
if (( CPUS < 32 )); then
    warn "config/experiment.yaml assumes 32 vCPU (c6i.8xlarge)."
    warn "With $CPUS, Fabric will crowd out the system under test and Exp 1 will"
    warn "saturate on contention, not on sharding. Update environment.vcpus and"
    warn "zkredact.sharding.counts, or resize the instance."
else
    ok "vCPU count matches the configured CPU budget"
fi
(( MEM_GB >= 60 ))  || warn "less than 64 GB RAM — Fabric plus a 10k-block ledger may be tight"
(( DISK_GB >= 150 )) || warn "less than 150 GB free — Docker images, ledgers and proving keys need room"

# -----------------------------------------------------------------------------
# Go
# -----------------------------------------------------------------------------
step "Go >= 1.$GO_MIN_MINOR"

go_minor() { go version 2>/dev/null | sed -n 's/.*go1\.\([0-9]*\).*/\1/p'; }

install_go() {
    local ver
    ver=$(curl -fsSL https://go.dev/VERSION?m=text 2>/dev/null | head -1 || true)
    [[ -n "$ver" ]] || die "could not resolve the latest Go version (network?)"

    local tarball="${ver}.linux-amd64.tar.gz"
    printf '     installing %s\n' "$ver"
    curl -fsSLO "https://go.dev/dl/${tarball}" || die "download failed: $tarball"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$tarball"
    rm -f "$tarball"

    if ! grep -q '/usr/local/go/bin' "$HOME/.bashrc" 2>/dev/null; then
        {
            echo ''
            echo '# Go (added by scripts/setup-ec2.sh)'
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'
        } >> "$HOME/.bashrc"
    fi
    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
}

export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
if command -v go >/dev/null 2>&1 && (( $(go_minor) >= GO_MIN_MINOR )); then
    ok "$(go version)"
elif [[ "$MODE" == "verify" ]]; then
    die "Go missing or older than 1.$GO_MIN_MINOR"
else
    install_go
    ok "$(go version)"
fi

# -----------------------------------------------------------------------------
# System packages
# -----------------------------------------------------------------------------
step "Build tools"

need_pkgs=()
command -v make    >/dev/null 2>&1 || need_pkgs+=(make)
command -v protoc  >/dev/null 2>&1 || need_pkgs+=(protobuf-compiler)
command -v gcc     >/dev/null 2>&1 || need_pkgs+=(build-essential)
command -v jq      >/dev/null 2>&1 || need_pkgs+=(jq)
# The AWS CLI is not a build dependency — it is how a shard PUBLISHES its
# results before the instance stops. scripts/run-shard.sh --s3 needs it, and a
# host without it finishes its work and then cannot hand it over. Found on a
# provisioned c6i.8xlarge: go and the Fabric binaries were present, aws was not.
command -v aws     >/dev/null 2>&1 || need_pkgs+=(awscli)
command -v curl    >/dev/null 2>&1 || need_pkgs+=(curl)
command -v git     >/dev/null 2>&1 || need_pkgs+=(git)

if (( ${#need_pkgs[@]} == 0 )); then
    ok "make, protoc, gcc, jq, curl, git"
elif [[ "$MODE" == "verify" ]]; then
    die "missing: ${need_pkgs[*]}"
else
    printf '     installing: %s\n' "${need_pkgs[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y -qq "${need_pkgs[@]}"
    ok "installed ${need_pkgs[*]}"
fi

if command -v protoc >/dev/null 2>&1; then
    pv=$(protoc --version | awk '{print $2}')
    if [[ "$(printf '%s\n%s\n' "$PROTOC_MIN" "$pv" | sort -V | head -1)" == "$PROTOC_MIN" ]]; then
        ok "protoc $pv"
    else
        warn "protoc $pv is below the required $PROTOC_MIN"
    fi
fi

# -----------------------------------------------------------------------------
# Go protobuf plugin
# -----------------------------------------------------------------------------
step "protoc-gen-go"

if command -v protoc-gen-go >/dev/null 2>&1; then
    ok "$(protoc-gen-go --version 2>&1 | head -1)"
elif [[ "$MODE" == "verify" ]]; then
    die "protoc-gen-go not on PATH (is \$HOME/go/bin exported?)"
else
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    ok "installed"
fi

# -----------------------------------------------------------------------------
# Docker
# -----------------------------------------------------------------------------
step "Docker"

if command -v docker >/dev/null 2>&1; then
    ok "$(docker --version)"
elif [[ "$MODE" == "verify" ]]; then
    die "Docker not installed"
else
    sudo apt-get install -y -qq docker.io docker-compose-v2
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER"
    ok "installed"
    # A GROUP ADDED HERE IS NOT IN THIS SHELL. usermod edits /etc/group, but the
    # running shell keeps the group set it was given at login, so every docker
    # call for the rest of this script hits the socket unprivileged. Measured on
    # a clean Ubuntu 22.04 c6i.8xlarge: the Fabric image pull failed with
    # "permission denied ... /var/run/docker.sock" on EVERY image and the script
    # exited 1 having installed Go and the binaries but no images.
    #
    # DOCKER_RUN re-enters the group for the commands that need it. Callers use
    # it instead of bare docker, and a login shell later gets the membership the
    # normal way.
    warn "log out and back in before Docker works without sudo in a new shell"
fi

# How to invoke docker for the rest of THIS script. `sg docker -c` runs a
# command with the group applied; where that is unavailable, sudo is the
# fallback. An already-effective membership needs neither.
DOCKER_RUN=""
if ! docker info >/dev/null 2>&1; then
    if command -v sg >/dev/null 2>&1 && sg docker -c "docker info" >/dev/null 2>&1; then
        DOCKER_RUN="sg docker -c"
    elif sudo docker info >/dev/null 2>&1; then
        DOCKER_RUN="sudo_shell"
    fi
fi

# run_docker executes a shell command with docker reachable, whichever route works.
run_docker() {
    case "$DOCKER_RUN" in
        "sg docker -c") sg docker -c "$1" ;;
        sudo_shell)     sudo -E bash -c "$1" ;;
        *)              bash -c "$1" ;;
    esac
}

if docker compose version >/dev/null 2>&1; then
    ok "$(docker compose version)"
else
    warn "docker compose v2 plugin not found"
fi

if run_docker "docker info" >/dev/null 2>&1; then
    if [[ -n "$DOCKER_RUN" ]]; then
        ok "docker daemon reachable (via ${DOCKER_RUN/sudo_shell/sudo}, group not yet in this shell)"
    else
        ok "docker daemon reachable"
    fi
else
    warn "cannot reach the docker daemon by any route — Fabric images cannot be pulled"
fi

# -----------------------------------------------------------------------------
# Hyperledger Fabric
# -----------------------------------------------------------------------------
step "Hyperledger Fabric $FABRIC_VERSION"

FABRIC_DIR="$HOME/fabric"

if [[ -x "$FABRIC_DIR/bin/peer" ]]; then
    ok "$("$FABRIC_DIR/bin/peer" version 2>/dev/null | head -1)"
elif [[ "$MODE" == "verify" ]]; then
    die "Fabric binaries not found at $FABRIC_DIR/bin"
else
    mkdir -p "$FABRIC_DIR"
    pushd "$FABRIC_DIR" >/dev/null
    curl -fsSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh \
        || die "could not download install-fabric.sh"
    chmod +x install-fabric.sh
    # binary + docker: skip the samples repo, we have our own network config
    run_docker "./install-fabric.sh --fabric-version '$FABRIC_VERSION' \
                        --ca-version '$FABRIC_CA_VERSION' binary docker" \
        || die "Fabric install failed"
    popd >/dev/null

    if ! grep -q "fabric/bin" "$HOME/.bashrc" 2>/dev/null; then
        {
            echo ''
            echo '# Hyperledger Fabric (added by scripts/setup-ec2.sh)'
            echo "export PATH=\$PATH:$FABRIC_DIR/bin"
            echo "export FABRIC_CFG_PATH=$FABRIC_DIR/config"
        } >> "$HOME/.bashrc"
    fi
    ok "installed to $FABRIC_DIR"
fi

# -----------------------------------------------------------------------------
# Project
# -----------------------------------------------------------------------------
step "Project dependencies"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -f go.mod ]]; then
    if [[ "$MODE" == "install" ]]; then
        go mod tidy && ok "go mod tidy"
    fi
    go vet ./cmd/... 2>/dev/null && ok "go vet ./cmd/... clean" \
        || warn "go vet reported issues — the validator has not been compiled before"
else
    warn "no go.mod at $REPO_ROOT"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
step "Summary"

printf '     %-18s %s\n' "Go"      "$(go version 2>/dev/null | awk '{print $3}' || echo MISSING)"
printf '     %-18s %s\n' "protoc"  "$(protoc --version 2>/dev/null | awk '{print $2}' || echo MISSING)"
printf '     %-18s %s\n' "Docker"  "$(docker --version 2>/dev/null | awk '{print $3}' | tr -d , || echo MISSING)"
printf '     %-18s %s\n' "Fabric"  "$("$FABRIC_DIR/bin/peer" version 2>/dev/null | sed -n 's/.*Version: //p' | head -1 || echo MISSING)"
printf '     %-18s %s vCPU / %s GB\n' "Host" "$CPUS" "$MEM_GB"

cat <<EOF

${BLD}Next${RST}
  source ~/.bashrc                    # or log out and back in for the docker group
  make validate-config                # first real check of config/experiment.yaml
  ./scripts/setup-ec2.sh verify       # re-check this install at any time

${BLD}Cost${RST}
  c6i.8xlarge runs roughly \$1.4/hour on demand. ${YLW}Stop the instance when idle${RST}
  — left running it is about \$34/day, and storage alone is a few dollars a month.
EOF
