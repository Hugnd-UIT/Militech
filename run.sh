#!/usr/bin/env bash
set -euo pipefail

# Prevent Git Bash / MSYS2 from rewriting container paths like /outputs
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="militech:latest"

TARGET=""
BRANCH=""
KEEP=0
REBUILD=0
FORWARD_ARGS=()

usage() {
    echo "Usage: bash run.sh <git_url_or_local_path> [--branch <tag>] [--keep] [--rebuild] [--provider openai|anthropic]"
    exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage 0
            ;;
        --branch|-b)
            BRANCH="${2:-}"
            [[ -n "$BRANCH" ]] || usage
            FORWARD_ARGS+=("--branch" "$BRANCH")
            shift 2
            ;;
        --keep)
            KEEP=1
            shift
            ;;
        --rebuild)
            REBUILD=1
            shift
            ;;
        --provider)
            FORWARD_ARGS+=("--provider" "${2:-openai}")
            shift 2
            ;;
        -*)
            FORWARD_ARGS+=("$1")
            shift
            ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
            else
                FORWARD_ARGS+=("$1")
            fi
            shift
            ;;
    esac
done

[[ -n "$TARGET" ]] || usage

to_docker_path() {
    local p="$1"
    if [[ "$DOCKER_BIN" == *.exe ]] && command -v wslpath >/dev/null 2>&1; then
        wslpath -m "$p"
    elif command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$p"
    else
        echo "$p"
    fi
}

DOCKER_BIN="docker"
if ! command -v docker >/dev/null 2>&1 && command -v docker.exe >/dev/null 2>&1; then
    DOCKER_BIN="docker.exe"
fi

# Build militech:latest if missing or --rebuild requested
if [[ "$REBUILD" -eq 1 ]] || ! "$DOCKER_BIN" image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[*] Building $IMAGE..."
    "$DOCKER_BIN" build -t "$IMAGE" -f "$SCRIPT_DIR/docker/Dockerfile" "$SCRIPT_DIR"
fi

# Derive clean repo name & per-repo container slug
CLEAN_TARGET="${TARGET%/}"
REPO_NAME="$(basename "$CLEAN_TARGET")"
REPO_NAME="${REPO_NAME%.git}"
[[ -n "$REPO_NAME" ]] || REPO_NAME="target"
SLUG="$(echo "$REPO_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/-/g')"
CONTAINER_NAME="militech-$SLUG"

OUT_DIR="$SCRIPT_DIR/outputs/$REPO_NAME"
mkdir -p "$OUT_DIR"

DOCKER_ARGS=(
    run -i
    --name "$CONTAINER_NAME"
    --cap-add=NET_ADMIN
    --cap-add=SYS_PTRACE
    --add-host=host.docker.internal:host-gateway
    -e "MILITECH_CONTAINER_NAME=$CONTAINER_NAME"
    -v "$(to_docker_path "$OUT_DIR"):/outputs:rw"
)

if [[ -t 0 && -t 1 ]]; then
    DOCKER_ARGS+=(-t)
fi

if [[ "$KEEP" -eq 0 ]]; then
    DOCKER_ARGS+=(--rm)
fi

if [[ -f "$SCRIPT_DIR/config/config.yml" ]]; then
    DOCKER_ARGS+=(-v "$(to_docker_path "$SCRIPT_DIR/config/config.yml"):/app/config/config.yml:ro")
fi

CONTAINER_TARGET="$TARGET"
if [[ -d "$TARGET" ]]; then
    ABS_TARGET="$(cd "$TARGET" && pwd)"
    DOCKER_ARGS+=(-v "$(to_docker_path "$ABS_TARGET"):/host_repo:ro")
    CONTAINER_TARGET="/host_repo"
fi

# Clean up exited container with same name if left from a previous --keep/crash run
if "$DOCKER_BIN" ps -a --format '{{.Names}} {{.State}}' | grep -q "^${CONTAINER_NAME} exited$"; then
    "$DOCKER_BIN" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

echo "[*] Launching $CONTAINER_NAME (outputs -> outputs/$REPO_NAME)"
exec "$DOCKER_BIN" "${DOCKER_ARGS[@]}" "$IMAGE" \
    "$CONTAINER_TARGET" \
    --outputs /outputs \
    --in-container \
    "${FORWARD_ARGS[@]}"
