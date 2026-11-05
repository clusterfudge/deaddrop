#!/bin/sh
# --deliver-cmd for the rotation harness: the invite URL arrives on stdin and is
# written to a 0600 file in the run's work dir; nothing is emailed or printed.
set -eu
umask 077
: "${DDFLEET_DELIVERED:?set by fleet_e2e.py}"
mkdir -p "$DDFLEET_DELIVERED"
cat > "$DDFLEET_DELIVERED/${DEADROP_INVITE_IDENTITY:-unknown}.url"
echo "${DEADROP_INVITE_IDENTITY:-unknown} ${DEADROP_INVITE_EXPIRES:-?} to=${DEADROP_INVITE_TO:+set}" >> "$DDFLEET_DELIVERED/deliveries.log"
