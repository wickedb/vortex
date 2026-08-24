#!/bin/bash
# How much of a grantee's read stream ever reaches the enforcement point?
#
# The checker is spliced into the L3 -> DRAM binding, so every level above it
# is a blind spot: 16 KB L1 per core, 1 MB L2 per cluster, 2 MB L3. A read that
# hits in any of them never becomes a MemReq at the checker, so no policy —
# owner, perms, epoch — is consulted for it. Revocation acts on the miss stream
# and only on the miss stream.
#
# Method (application-level, no simulator change): run the live-grant phase
# twice at each working-set size, differing only in the iteration count. The
# extra iterations issue a known number of extra grantee loads; the change in
# the checker's own `checked` counter is how many of them reached the checker.
#
#   coverage       = d(checked) / d(reads)     fraction of reads any policy saw
#   blind window   = d(reads) / d(checked)     reads the grantee gets per
#                                              opportunity the checker has to
#                                              stop it — i.e. how long
#                                              "eventually" is, in reads
#
# Usage: sweep.sh [extra blackbox.sh args...]        (run from the build dir)
#   e.g. sweep.sh                 # L1 only  (16 KB/core)
#        sweep.sh --l2cache       # + 1 MB L2
#        sweep.sh --l2cache --l3cache   # + 2 MB L3, the paper's full config
set -u
BB=${BB:-./ci/blackbox.sh}
TASKS=${TASKS:-64}
I1=${I1:-2048}
I2=${I2:-6144}
WS=${WS:-"256 1024 4096 16384 65536 262144"}

run() { # ws iters -> "reads checked"
  local out
  out=$(VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_STATS=1 $BB --driver=simx --cores=2 \
          --app=revoke_window --args="-n$TASKS -w$1 -i$2 -P1" ${EXTRA[@]+"${EXTRA[@]}"} 2>&1)
  local reads checked
  reads=$(echo "$out"   | sed -n 's/.*GRANTEE_READS .*phase1=\([0-9]*\).*/\1/p' | tail -1)
  checked=$(echo "$out" | sed -n 's/.*CHECKER: reqs=[0-9]*, checked=\([0-9]*\).*/\1/p' | tail -1)
  echo "${reads:-} ${checked:-}"
}

EXTRA=("$@")
printf '%9s %9s %12s %12s %10s %14s\n' \
  WS_BYTES LINES D_READS D_CHECKED COVERAGE 'BLIND_WINDOW'
for w in $WS; do
  read -r r1 c1 <<<"$(run "$w" "$I1")"
  read -r r2 c2 <<<"$(run "$w" "$I2")"
  if [ -z "${r1:-}" ] || [ -z "${c1:-}" ] || [ -z "${r2:-}" ] || [ -z "${c2:-}" ]; then
    printf '%9s %9s %12s\n' "$((w*4))" "$(((w+15)/16))" "no result"; continue
  fi
  dr=$(( r2 - r1 )); dc=$(( c2 - c1 ))
  [ "$dc" -lt 0 ] && dc=0
  cov=$(awk -v dr="$dr" -v dc="$dc" 'BEGIN{ if (dr>0) printf "%.5f", dc/dr; else printf "0" }')
  win=$(awk -v dr="$dr" -v dc="$dc" 'BEGIN{ if (dc>0) printf "%.1f", dr/dc; else printf "unbounded" }')
  printf '%9s %9s %12s %12s %10s %14s\n' \
    "$((w*4))" "$(((w+15)/16))" "$dr" "$dc" "$cov" "$win"
done
