#!/usr/bin/env bash
# Started by record.sh's socat once per accepted connection (stdin/stdout = client).
# Kept as a separate script because socat treats ':' inside SYSTEM:<cmd> as a parameter separator.
exec socat -r "$TRACE/c2s.$$.bin" -R "$TRACE/s2c.$$.bin" -v STDIO UNIX-CONNECT:"$PG_SOCK" 2>"$TRACE/log.$$.txt"
