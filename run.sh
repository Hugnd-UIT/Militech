#!/usr/bin/env bash
set -euo pipefail

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"
IMAGE="militech:latest"

TARGET=""
BRANCH=""
REBUILD=0

usage() {
    echo "Usage: bash run.sh <owner/repo | git_url | local_path> [--branch <tag>] [-f|--rebuild]"
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
            shift 2
            ;;
        --rebuild|-f)
            REBUILD=1
            shift
            ;;
        -*)
            echo "[!] Unknown option: $1"
            usage
            ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
            fi
            shift
            ;;
    esac
done

[[ -n "$TARGET" ]] || usage

DOCKER_BIN="docker"
if ! command -v docker >/dev/null 2>&1 && command -v docker.exe >/dev/null 2>&1; then
    DOCKER_BIN="docker.exe"
fi

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

if [[ ! -d "$TARGET" ]] && [[ "$TARGET" != *"://"* ]] && [[ "$TARGET" != git@* ]] && [[ "$TARGET" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    TARGET="https://github.com/$TARGET.git"
fi

CLEAN_TARGET="${TARGET%/}"
REPO_NAME="$(basename "$CLEAN_TARGET")"
REPO_NAME="${REPO_NAME%.git}"
[[ -n "$REPO_NAME" ]] || REPO_NAME="target"
REPO_SLUG="$(echo "$REPO_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/-/g')"
CONTAINER_NAME="militech-$REPO_SLUG"

OUT_DIR="$SCRIPT_DIR/outputs/$REPO_NAME"
mkdir -p "$OUT_DIR" 2>/dev/null || true

export TARGET BRANCH REPO_NAME REPO_SLUG
export ROOT_DIR="$(to_docker_path "$SCRIPT_DIR")"
export HOST_OUTPUTS="$(to_docker_path "$OUT_DIR")"
export HOST_CONFIG="$(to_docker_path "$SCRIPT_DIR/config/config.yml")"

if "$DOCKER_BIN" ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    echo "[!] Container $CONTAINER_NAME is already running. Logs: docker logs -f $CONTAINER_NAME"
    exit 1
fi

if [[ "$REBUILD" -eq 1 ]] || ! "$DOCKER_BIN" image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[*] Image $IMAGE not found or --rebuild specified. Building..."
    BUILD_ARGS=()
    [[ "$REBUILD" -eq 1 ]] && BUILD_ARGS+=(--no-cache)
    "$DOCKER_BIN" build "${BUILD_ARGS[@]}" -t "$IMAGE" -f "$SCRIPT_DIR/docker/Dockerfile" "$SCRIPT_DIR"
fi

"$DOCKER_BIN" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

DOCKER_ARGS=(
    run -d
    --name "$CONTAINER_NAME"
    --cap-add=NET_ADMIN --cap-add=SYS_PTRACE
    --add-host=host.docker.internal:host-gateway
    -e PYTHONUNBUFFERED=1
    -e PYTHONDONTWRITEBYTECODE=1
    -e PYTHONPATH=/app
    -e "CONTAINER_NAME=$CONTAINER_NAME"
    -v "$ROOT_DIR:/app:rw"
    -v "$HOST_OUTPUTS:/outputs:rw"
)
[[ -f "$SCRIPT_DIR/config/config.yml" ]] && DOCKER_ARGS+=(-v "$HOST_CONFIG:/app/config/config.yml:ro")

if [[ -d "$TARGET" ]]; then
    ABS_TARGET="$(cd "$TARGET" && pwd)"
    DOCKER_ARGS+=(-v "$(to_docker_path "$ABS_TARGET"):/host_repo:ro")
    "$DOCKER_BIN" "${DOCKER_ARGS[@]}" "$IMAGE" /host_repo >/dev/null
else
    CMD_ARGS=("$TARGET")
    [[ -n "$BRANCH" ]] && CMD_ARGS+=(--branch "$BRANCH")
    "$DOCKER_BIN" "${DOCKER_ARGS[@]}" "$IMAGE" "${CMD_ARGS[@]}" >/dev/null
fi

echo "[+] Started $CONTAINER_NAME in background"
echo "    Logs: docker logs -f $CONTAINER_NAME"
echo "    Stop: docker stop $CONTAINER_NAME"