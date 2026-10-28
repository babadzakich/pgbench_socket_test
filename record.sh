#!/usr/bin/env bash
# Record pgbench <-> PostgreSQL traffic over Unix domain sockets with socat.
# Usage: ./record.sh [pgbench args...]   (default: -c 8 -j 8 -T 10 -M prepared)
set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
PGBIN=${PGBIN:-}                        # directory with pgbench; empty = take it from PATH
PORT=5432
PG_SOCK=$DIR/pgsock/.s.PGSQL.$PORT     # real server socket
PROXY_DIR=$DIR/proxy                   # pgbench connects here
TRACE=${TRACE:-$DIR/trace/$(date +%Y%m%d-%H%M%S)}

[[ -S $PG_SOCK ]] || { echo "server socket $PG_SOCK not found, start PostgreSQL first" >&2; exit 1; }
mkdir -p "$PROXY_DIR" "$TRACE"

# One child socat per connection: c2s = client->server bytes, s2c = server->client bytes.
export TRACE PG_SOCK
socat UNIX-LISTEN:"$PROXY_DIR/.s.PGSQL.$PORT",fork,mode=777,unlink-early \
  EXEC:"$DIR/rec_child.sh" &
SOCAT_PID=$!
trap 'kill $SOCAT_PID 2>/dev/null; rm -f "$PROXY_DIR/.s.PGSQL.$PORT"' EXIT
sleep 0.5

if [[ $# -eq 0 ]]; then set -- -c 8 -j 8 -T 10 -M prepared; fi
"${PGBIN:+$PGBIN/}pgbench" -h "$PROXY_DIR" -p "$PORT" "$@" bench | tee "$TRACE/pgbench.txt"

sleep 0.5
echo "trace written to $TRACE:"
ls -la "$TRACE"
