#!/bin/bash
# Tier-3 policy-churn amortization curve (PROJECT.md §12, figure 3).
#
# For each work-per-epoch point, runs the workload twice — churn and control —
# and differences the cycle counts. Identical launches, identical work; the only
# difference is the 9 DCR ring writes per epoch (7 re-grant + 2 revoke) and the
# launch-boundary drain they ride.
#
#   policy_cycles   = cycles(churn) - cycles(control)
#   per_epoch       = policy_cycles / epochs
#   policy_share    = policy_cycles / cycles(churn)
#
# Sweeping --taps moves work-per-epoch while the per-epoch policy cost stays
# fixed, which is what makes this an amortization curve rather than two
# confounded variables. The shape to expect is the Blackwell CC-tax analogue:
# a large share at small work-per-epoch falling toward zero as the kernel grows.
#
# THE INVALIDATE BAND. No invalidate primitive exists (PROJECT.md §10 #9) and
# SimX's per-launch reset is stronger than anything the design can issue, so the
# measured per-epoch cost EXCLUDES it. Per §10 #9 the curve therefore ships with
# the invalidate as a bounded unknown, swept 0 -> full-flush, applied here in
# post-processing. §10 #9 is explicit that the band must be drawn rather than
# hand-waved, and that the conclusion has to be checked against its worst end.
#
# INV_CYCLES is the sweep of assumed per-revocation invalidate costs. The upper
# end should be a full-hierarchy flush; measure it rather than guessing, and
# until then treat the top of the band as a placeholder, not a result.
#
# Usage (from the build dir):
#   tests/regression/churn/sweep.sh [extra blackbox args...]
#   TAPS="1 2 4 8 ..." EPOCHS=8 N=4096 CHUNKS=4 sweep.sh --l2cache --l3cache
set -u

BB=${BB:-./ci/blackbox.sh}
N=${N:-4096}
EPOCHS=${EPOCHS:-8}
CHUNKS=${CHUNKS:-4}
TAPS=${TAPS:-"1 2 4 8 16 32 64 128"}
INV_CYCLES=${INV_CYCLES:-"0 64 256 1024 4096"}
OUT=${OUT:-churn_sweep.csv}

run_cycles() {
  # echoes the cycle count, or empty on failure
  local mode=$1 taps=$2; shift 2
  local log
  log=$(VX_CHECKER=1 VX_CHECKER_STATS=1 \
        $BB --driver=simx --app=churn --cores=2 --perf=1 \
            --args="-n$N -t$taps -e$EPOCHS -c$CHUNKS -m$mode" "$@" 2>&1) || true
  if ! grep -q "PASSED" <<<"$log"; then
    echo "  !! mode=$mode taps=$taps did NOT pass — excluded" >&2
    grep -E "mismatch|FAILED|deny=" <<<"$log" | head -3 >&2
    return 1
  fi
  # guard the counters §8.4 says to check before trusting a run at all
  if grep -qE "claims: rejected=[1-9]|aliased=[1-9]" <<<"$log"; then
    echo "  !! mode=$mode taps=$taps had a refused claim — buffer UNPROTECTED, excluded" >&2
    return 1
  fi
  grep -oE "cycles=[0-9]+" <<<"$log" | head -1 | cut -d= -f2
}

echo "taps,work_per_epoch,cycles_control,cycles_churn,policy_cycles,per_epoch_cycles,policy_share_pct" > "$OUT"
echo "# n=$N epochs=$EPOCHS chunks=$CHUNKS  extra: $*" >> "$OUT"

for t in $TAPS; do
  c0=$(run_cycles 0 "$t" "$@") || continue
  c1=$(run_cycles 1 "$t" "$@") || continue
  [ -n "$c0" ] && [ -n "$c1" ] || continue
  pol=$(( c1 - c0 ))
  per=$(awk -v p="$pol" -v e="$EPOCHS" 'BEGIN{printf "%.1f", p/e}')
  shr=$(awk -v p="$pol" -v c="$c1" 'BEGIN{printf "%.4f", (c>0)?100.0*p/c:0}')
  wpe=$(( N * t ))
  echo "$t,$wpe,$c0,$c1,$pol,$per,$shr" | tee -a "$OUT"
done

echo
echo "=== invalidate sensitivity band (PROJECT.md §10 #9) ==="
echo "Measured per-epoch cost EXCLUDES the invalidate, which does not exist."
echo "Columns add an assumed per-revocation invalidate cost to every epoch."
echo
printf "taps"
for inv in $INV_CYCLES; do printf ",share_inv%s" "$inv"; done
printf "\n"
tail -n +3 "$OUT" | while IFS=, read -r t wpe c0 c1 pol per shr; do
  [ -n "${t:-}" ] || continue
  printf "%s" "$t"
  for inv in $INV_CYCLES; do
    # adding INV per epoch inflates both the policy cost and the total
    awk -v p="$pol" -v c="$c1" -v e="$EPOCHS" -v i="$inv" \
        'BEGIN{ pp=p+e*i; cc=c+e*i; printf ",%.4f", (cc>0)?100.0*pp/cc:0 }'
  done
  printf "\n"
done
echo
echo "Wrote $OUT"
echo "Check the worst column: if the conclusion does not survive it, that is a"
echo "finding about the design (PROJECT.md §10 #9), not a reason to narrow the band."
