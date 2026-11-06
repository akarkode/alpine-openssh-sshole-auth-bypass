#!/usr/bin/env bash
# A/B check: same lab, but with the fixed Alpine package (9.9_p2-r1).
# The 257..1024 byte passwords must be rejected here.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
NET="sshole-lab"
FIXED="sshole-server-fixed"

echo "[*] Building FIXED server image (openssh 9.9_p2-r1)..."
docker build -q --build-arg OPENSSH_VER=9.9_p2-r1 \
    -t "$FIXED" -f "$DIR/server.Dockerfile" "$DIR"

echo "[*] Building client image..."
docker build -q -t sshole-client -f "$DIR/client.Dockerfile" "$DIR"

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$FIXED" >/dev/null 2>&1 || true

echo "[*] Starting fixed sshd..."
docker run -d --name "$FIXED" --network "$NET" "$FIXED" >/dev/null
for _ in $(seq 1 40); do
    if docker exec "$FIXED" sh -c 'netstat -ltn 2>/dev/null | grep -q ":22 "' 2>/dev/null; then
        break
    fi
    sleep 0.5
done

echo
docker logs "$FIXED" 2>&1 | sed 's/^/    /'
echo
echo "[*] Running the same exploit against the FIXED server..."
echo "    (expected: 257/300/1024 rejected, donor still accepted)"
echo
HOST="$FIXED" docker run --rm --network "$NET" -e HOST="$FIXED" sshole-client

echo
docker rm -f "$FIXED" >/dev/null
