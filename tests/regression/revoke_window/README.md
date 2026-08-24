# revoke_window — how much of a grantee's read stream reaches the checker?

Backs thesis finding M3, *"revocation is unenforceable within a launch."*
Everything here is application code — host program, kernel, shell script. No
simulator modification, no privileged counter on the measured path. That is
deliberate: a demonstration that needs a change to the machine it is
demonstrating on proves nothing about the machine.

## The claim

The checker is spliced into the `l3cache_ -> memsim_` binding
(`sim/simx/sec/mem_checker.h`), which is the off-chip boundary. Every level
above it is a blind spot:

| level | size | above the checker? |
|---|---|---|
| L1 D-cache | 16 KB / core, 4-way, 64 B lines | yes |
| L2 | 1 MB / cluster | yes |
| L3 | 2 MB | yes |
| policy granule | 1 MB (`buffer_log2 = 20`) | — |

A read that hits in any of those never becomes a `MemReq` at the checker, so no
policy — owner, perms, epoch — is consulted for it. **Revocation acts on the
miss stream and only on the miss stream.** The granule the policy is written in
is 1 MB; the blind spot is 3 MB. A whole granule fits inside it with room over.

## What is measured

A grantee runs a dependent pointer-chase over a working set of `-w` words: each
word holds the index of the next, shuffled so one word is touched per 64 B line
and no stride prefetcher (and no reviewer) can attribute the result to anything
but the level the line is resident in.

Run the live-grant phase twice at each working-set size, differing only in the
iteration count. The extra iterations issue a known number of extra grantee
loads; the change in the checker's own `checked` counter is how many of them
reached the checker.

    coverage     = d(checked) / d(reads)   fraction of reads any policy saw
    blind window = d(reads) / d(checked)   reads the grantee gets per
                                           opportunity the checker has to stop
                                           it — how long "eventually" is

## Results

`--cores=2`, L1 only, 8192 extra grantee reads at each point:

| working set | lines | Δreads | Δchecked | coverage | blind window |
|---|---|---|---|---|---|
| 1 KB | 16 | 8192 | 0 | 0.00000 | unbounded |
| 4 KB | 64 | 8192 | 0 | 0.00000 | unbounded |
| 16 KB | 256 | 8192 | 0 | 0.00000 | unbounded |
| 32 KB | 512 | 8192 | 8192 | 1.00000 | 1.0 |
| 64 KB | 1024 | 8192 | 8192 | 1.00000 | 1.0 |
| 128 KB | 2048 | 8192 | 8192 | 1.00000 | 1.0 |
| 256 KB | 4096 | 8192 | 8192 | 1.00000 | 1.0 |

The knee is exactly the 16 KB L1 capacity. At or below it the coverage is not
"small", it is zero: 8192 additional reads produced zero additional checked
requests. With `--l2cache --l3cache` — the full hierarchy the artifact reports
validating against — the same zero holds out to megabytes.

The second measurement is the enforcement rate itself. In the post-revocation
phase the application observes 4096 denied reads at a 4 KB working set, and the
checker reports `deny=64` for the whole run: **one enforcement event per line,
not per access.** For a working set of L lines and R reads the checker gets at
most L opportunities however large R is. Once the set is resident, L is already
spent, and the count is exactly zero.

## What this does and does not show

It does **not** show a revocation landing inside a launch, because no
application can make that happen. `vx_dcr_write` wraps the same queue as
`vx_enqueue_dcr_write`, and the ring engine's `WaitDone` state
(`sim/common/cmd_processor.cpp:582`) blocks until the launch FSM idles. Every
revocation the API can express lands at a launch boundary — behind exactly the
control-plane round-trip that §5 and §8 criticise CC for. The device-resident
path is closed on purpose: `dcr_write_indirect_` refuses the whole checker
window, so a draw bundle cannot revoke either.

Two things follow, and they are what the paper should say:

1. **The demonstrated property is cross-launch, not intra-launch.** `revoke`
   passes because SimX re-enters `ProcessorImpl::run()` per launch and
   `reset()` wipes every cache set. That wipe is not a primitive the design
   has. In this tree `Cache::flush_begin()` early-exits on write-through caches
   (`sim/simx/mem/cache.cpp:639`) and `processFlush()` clears `dirty` but never
   `valid` (`:1594`). A flush writes back; it does not invalidate. So the cost
   M2 asks the paper to add — the device-wide shootdown — would not close M3
   even if it were paid: it leaves the readable copies in place.

2. **The right scoping sentence.** Revocation holds for tenants separated by a
   full cache invalidate. It is not enforceable against a co-resident tenant
   whose working set fits above the checker, which is the adversary §4 names.

## Running

    # from the build directory
    VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_STATS=1 \
      ./ci/blackbox.sh --driver=simx --cores=2 --app=revoke_window \
      --args="-n64 -w1024 -i2048"

    # the sweep
    ./tests/regression/revoke_window/sweep.sh                    # L1 only
    ./tests/regression/revoke_window/sweep.sh --l2cache --l3cache

`-P1` runs the live-grant phase only, `-P2` the revocation and the phase after
it, `-P3` (default) both. The sweep uses `-P1` so the differential is
attributable to the grantee's reads under a live grant and nothing else.
