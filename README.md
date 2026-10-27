# invariant-vacuity

Finds Foundry invariant tests that pass for the wrong reason.

An invariant test that passes tells you the property held over the states the fuzzer
reached. It does not tell you the fuzzer reached any interesting state. If every handler
call reverts, if the handler never touches the contract the invariant reads, or if the
invariant only reads a value nothing can change, the test passes forever and proves
nothing. `vacuity` runs your invariant suite, then runs it again through a probe that
watches what each invariant actually reads, and tells you which invariants never saw any
of their inputs change.

It is a CI gate. An error means your own campaign gave evidence the invariant was checked
against unchanging inputs that no code that ran can write. A warning is worth a look.

Excerpt from a real run on [keldxd/erc4626-invariants](https://github.com/keldxd/erc4626-invariants)
(long lines wrapped and shortened with `[...]`):

```
test/reference/OpenZeppelinVault.t.sol:OpenZeppelinVaultTest
  campaigns: 7 (one per invariant), up to 256 runs each, 179200 calls and 0 reverts in total
  ok       invariant_backing()
  guarded  invariant_limitsAreHonest()
           none of its 2 inputs changed during 25600 probe calls. Code that ran during the
           campaign can write them (ERC4626Handler.deposit writes maxDepositViolated
           (conditionally); [...]), yet they never changed. [...]
  ok       invariant_noValueCreated()
  FROZEN   invariant_noZeroShareDeposits()
           reads no storage, balance or environment value, so its result cannot change (25600 probe calls)
  [...]
summary: 1 error, 7 warnings
```

The error is real: for this vault the suite's `_rejectZeroShareDeposits()` returns false,
so `invariant_noZeroShareDeposits` returns on its first line and can never fail. In that
repo it is a deliberate opt-out; `--ignore OpenZeppelinVaultTest.invariant_noZeroShareDeposits`
records that decision. The `guarded` lines are violation flags the handler only sets
when it sees a bug, which is what a correct vault should produce.

## Install

Requires Python 3.9 or newer and Forge 1.1.0 or newer. No Python dependencies. Tested on
Linux (CI runs Ubuntu); macOS should work but is not tested yet; Windows is not supported.

```
pip install git+https://github.com/keldxd/invariant-vacuity
```

or run it from a checkout with `python -m vacuity`.

## Use

From your Foundry project root:

```
vacuity                                   # whole project
vacuity --match-path 'test/invariant/*'   # some files
vacuity --match-contract VaultInvariants  # some contracts
vacuity --strict                          # fail on warnings too
vacuity --format json --json-out report.json
vacuity -- --fork-url $RPC_URL --fork-block-number 19000000
```

Arguments after `--` go to `forge test`. Your `foundry.toml` profile is respected
(`FOUNDRY_PROFILE=ci vacuity` works), including `runs`, `depth`, `fail_on_revert`,
`match_*` / `no_match_*` filters, custom `src` / `test` / `out` / `cache_path` folders,
remappings, and inline `forge-config:` comments on invariant contracts and functions.

Exit codes: `0` no errors, `1` at least one error (or a warning with `--strict`), `2` the
tool could not run (forge missing or too old, your project does not compile, bad
arguments).

### GitHub Actions

```yaml
- uses: foundry-rs/foundry-toolchain@v1
- uses: keldxd/invariant-vacuity@v0.1.0
  with:
    args: --match-path 'test/invariant/*'
```

The action writes `vacuity-report.json` (change with `json-out`).

## What it reports

### Errors

| code | meaning |
| --- | --- |
| `frozen` | During a full campaign none of the invariant's inputs changed, and no function that ran successfully in your campaign contains a write to any variable the invariant reads. The invariant was checked against the same state every time. |

An invariant that reads no storage, balance or environment value at all (`assert(1 + 1 == 2)`,
`assert(address(vault) != address(0))` after setUp) is also `frozen`.

### Warnings

| code | meaning |
| --- | --- |
| `frozen-guarded` | Inputs never changed, but code that ran can write them. Usually one of: the write goes to another instance or mapping key than the one the invariant reads, it sits behind a condition that was never true, or it always wrote the same value. A violation flag on a correct implementation (`bool broken` only set when a bug happens) lands here, which is expected. The report lists the writes it found so you can decide. |
| `frozen-untracked` | Tracked inputs never changed, but the invariant also uses something the probe cannot compare (see Limitations), so it cannot prove the invariant was frozen. |
| `probe-inconclusive` | The probe could not judge this invariant: setUp reverted inside the probe, the invariant uses more gas than the probe will record, or the state after setUp differed between the probe's two runs (a fork of the latest block, randomness in setUp). |
| `dead-selector` | A target function reverted in every executed call. |
| `high-revert-selector` | A target function reverted in at least 90% of executed calls. |
| `high-discard` | At least 50% of a function's calls were thrown away by `vm.assume`. |
| `all-calls-reverted` | Every call in a campaign reverted. |
| `high-revert-campaign` | At least 75% of a campaign's calls reverted. |
| `no-calls` | The campaign made zero calls. |
| `setup-failed`, `metrics-missing`, `probe-missing` | Self-explanatory; the message says what happened. |

Thresholds are configurable (`--selector-revert-threshold`, `--campaign-revert-threshold`,
`--discard-threshold`). Findings can be suppressed with `--ignore`, which takes globs
against `Contract`, `Contract.invariant_x` or `Handler.selector` (repeatable).

Invariants that fail in your own run are reported as `failing` (info): the test is
already doing its job and is not judged.

## How it works

1. **Your run.** `forge test --json` on your invariant contracts, with metrics on. This
   gives the per-function call, revert and discard counts.
2. **Capture.** For each test contract `T`, a probe contract is generated into
   `test/__vacuity__/` (and deleted afterwards, also on Ctrl-C). The probe deploys `T`,
   runs `T.setUp()`, forwards all of `T`'s targeting settings (`targetContracts`,
   `targetSelectors`, `targetSenders`, `excludeSenders`, artifacts, interfaces and so
   on) so Forge fuzzes exactly what it fuzzes for `T`, then calls each invariant once
   under Forge's state diff recorder and opcode tracer. That records every storage slot,
   ETH balance, code hash, block or transaction value and `vm.load` slot the invariant
   reads, in every contract it touches.
3. **Campaign.** The probe runs a normal invariant campaign of the same size as yours.
   Its invariants fail as soon as any recorded input differs from its value right after
   setUp. A probe invariant that passes the whole campaign means that input set never
   changed.
4. **Judge.** For invariants whose inputs never changed, a static pass over the AST
   looks for any write to those variables in code reachable from the target functions
   that actually succeeded at least once in your run. No such write: `frozen` (error).
   A write exists: `frozen-guarded` (warning).

The build goes into `cache/vacuity/` (inside your `cache_path`), so your own `out/` and
build cache are never touched. It is rebuilt from scratch whenever the Forge version or
the resolved config changes. Failure replay files and the corpus directory, if
configured, are isolated the same way. In that build `dynamic_test_linking` is turned
off (Forge 1.8 enables it by default and it rewrites `new X()` in test files, which would
make deployed code stop matching the artifacts; it only affects compile caching).

The probe is written as one file per test contract plus a shared base, and the capture
step runs in batches of at most 24 invariants, so memory stays bounded as suites grow.

## Limitations

Read these before trusting a clean report.

- **A clean report does not mean the suite is good.** `vacuity` finds invariants that
  were never exercised. An invariant whose inputs change all the time can still be weak,
  wrong, or miss the bug.
- **`live` is empirical.** It means an input changed at least once in the probe's
  campaign. It says nothing about how often or how well.
- **`frozen` is about this campaign size.** It means nothing changed in a campaign the
  same size as yours. An input that changes only after more calls than your config
  allows will look frozen; the static write check then usually turns that into
  `frozen-guarded`, not an error.
- **Slot granularity.** Inputs are storage slots. If an invariant reads one variable that
  shares a packed slot with another variable that does change, the invariant counts as
  live.
- **The write check is name and type based.** It does not model which instance,
  mapping key or branch a write hits. That is why such cases are warnings, not errors.
  It will not produce an error when a reachable function writes the variable; it can
  produce a warning where a human sees the write is impossible.
- **Opaque code is assumed to write.** Inline assembly `sstore`, `delegatecall` to an
  unknown target, and `vm.store` make the write check assume any variable may be written,
  which keeps those cases as warnings.
- **Untracked inputs.** `block.basefee`, `block.prevrandao`, `block.blobbasefee`,
  `blockhash()`, `blobhash()`,
  and cheatcodes whose results the probe cannot compare (for example `vm.getNonce`,
  `vm.readFile`, `vm.ffi`, RPC cheatcodes) make a frozen result `frozen-untracked`. Unknown
  cheatcodes are treated as untracked.
- **Gas caps.** Forge's recorders are memory hungry, so the probe only records an
  invariant call up to 5,000,000 gas (`--record-gas`) and only opcode-traces it up to
  300,000 gas (`--trace-gas`). Above the first cap the invariant is `inconclusive`. Above
  the second, balance and environment reads are not tracked precisely: a live result
  stays live, a frozen result becomes `frozen-untracked`. Raising the caps costs memory
  (about 400 bytes per traced gas in Forge).
- **Forks.** Fork tests work. Pin the block (`--fork-block-number` or
  `createSelectFork(url, block)`). With a moving fork head, invariants whose inputs differ
  between the probe's two runs are `inconclusive`. Contracts that exist only on the fork
  and have no artifact in your project are named by address and cannot be write-checked,
  so frozen results on them are warnings.
- **setUp assumptions.** The probe deploys your test contract with `new` and calls
  `setUp()` from the probe's address. A setUp that depends on `msg.sender` being Forge's
  default test sender, or on the test contract's exact address, may behave differently
  and end up `inconclusive`. Test contracts whose constructor takes arguments are skipped.
- **Compiler settings after `--`.** Pass compiler settings through `foundry.toml` or
  `FOUNDRY_*` environment variables. Flags such as `--via-ir` after `--` only reach
  `forge test`, not the build `vacuity` reads, and lead to contracts the report cannot name.
- **One file, two compilers.** If a project compiles the same file with two solc
  versions in one build, the newest version's artifact is used and a note is printed.
- **Supported versions.** Forge 1.1.0 or newer (1.0.x crashes inside the state diff
  recorder), solc 0.8.0 or newer for the test contracts, Python 3.9 or newer.
- **Runtime and memory.** Expect roughly 1.3 to 2.5 times the time of your own
  `forge test`, and about 3 times its peak memory (numbers below). The opcode trace is the
  expensive part; `--trace-gas` and `--record-gas` trade precision for memory.
- `check_interval` and `afterInvariant` are not modeled specially.

## How it is tested

Every claim above is backed by a test in this repository or by a measurement listed
here. CI runs all the tests.

- **Seeded fixtures** (`fixtures/seeded`, 39 invariants). Twelve kinds of vacuous
  suite (handler always reverts, bounded to zero, ghost never updated, invariant reads an
  untouched slot, wrong target, excluded selector, trivially true, hash-gated branch,
  proxy bypass, wrong sender, time-dependent without warp, named slot never set), and
  seventeen healthy suites that must not be flagged (vm.load reads, time warps,
  `address(this).balance`, `BALANCE`, rare state changes, proxies, default targeting, no
  setUp, setUp needing ETH, `startPrank` in setUp, `targetSender`, helper libraries,
  non-view invariants, `statefulFuzz` prefix, large read sets, inherited setUp). Expected
  verdicts were written from each fixture's design before running the tool.
- **Edge fixtures** (`fixtures/edge`). setUp that reverts, invariant failing at the start,
  invariants above both gas caps, `excludeSender` forwarding, setUp storing `vm.unixTime()`.
- **Compatibility** (`fixtures/compat`). The same suite under solc 0.8.0, 0.8.4, 0.8.7,
  0.8.13, 0.8.19, 0.8.24 and 0.8.28, legacy and via-IR, optimizer on, `deny = "warnings"`,
  and `dynamic_test_linking = true`.
  The generated probe compiles with zero warnings on every one.
- **Project layout** (`fixtures/layout`). Custom `src`, `test`, `out` and `cache_path`,
  remappings, a `no_match_path` filter, file names with spaces.
- **`fail_on_revert = true`** (`fixtures/fail-on-revert`).
- **Forge versions.** The whole fixture matrix (14 setups) passes on Forge 1.1.0, 1.2.3,
  1.3.6, 1.4.4, 1.5.1, 1.7.1 and 1.8.6, 98 of 98, with build folders shared across
  versions and profiles. The seeded fixtures also pass under three different fuzz seeds
  on the oldest and newest version.
- **Integration tests** (`tests/test_integration.py`, 11 tests). The probe files are removed
  after every run, after a crash leftover, after a compile error and after Ctrl-C; your `out/`
  and build cache are byte-for-byte untouched; switching solc versions (pinned or by
  pragma) never reuses stale artifacts; `--ignore`, `--strict`, `--json-out`,
  `--from-json`, `--no-probe`, `--keep-probe`.
- **Fork tests** (`tests/test_fork.py`, 3 tests). Against a local anvil node: a pinned
  fork gives the normal verdicts; a fork of a moving head gives `inconclusive` only for
  the invariant whose input depends on the block; a contract that exists only on the fork,
  with no artifact, never produces an error.
- **Scale test** (`tests/scale_test.py`). 30 test contracts with 3 invariants each, every
  verdict checked; also run with 60 contracts whose frozen invariants read 101 slots each,
  which forces the probe inputs to be split across several Forge runs (180 of 180 correct,
  69 s, 359 MB peak).
- **Real suites.** Run on four public invariant suites; every error was checked by hand
  against the source (all were invariants that return before checking anything):

  | suite | invariants | your `forge test --json` | `vacuity` | result |
  | --- | --- | --- | --- | --- |
  | keldxd/erc4626-invariants | 14 | 53 s, 150 MB | 132 s, 451 MB | 1 error (opt-out above), 7 guarded flags |
  | same, `detection` profile (seeded bugs) | 42 | 128 s, 215 MB | 260 s, 675 MB | 9 failing, 5 errors (same opt-out), 9 guarded |
  | keldxd/aa-invariants | 42 | 83 s, 187 MB | 177 s, 524 MB | 0 errors, 10 guarded flags, 13 failing (seeded bugs) |
  | horsefacts/weth-invariant-testing | 5 | 29 s, 68 MB | 59 s, 236 MB | all live, clean |
  | lucas-manuel/invariant-examples | 14 | 28 s, 99 MB | 35 s, 305 MB | 7 high-revert warnings on the "open" handlers, 2 guarded |

  Measured on a 2 vCPU, 7 GB Linux machine with Forge 1.5.1. Memory is the largest single
  process.
- **GitHub Action.** CI runs the action from this repository on a fixture and checks the
  report it writes.
- **Unit tests** (`tests/test_unit.py`, 43 tests) for the parsers of every Forge JSON shape seen
  from 1.0 to 1.8, keccak, ABI encoding, the write graph and the artifact loader.

## License

MIT
