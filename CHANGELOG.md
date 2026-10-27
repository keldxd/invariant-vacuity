# Changelog

All notable changes to this project are listed here. Versions follow
[semantic versioning](https://semver.org).

## [0.1.0] - 2026-10-27

First release.

- Frozen-input probe: finds invariants whose inputs never changed during a full
  campaign. `frozen` (error) when no code that ran can write those inputs,
  `frozen-guarded` and `frozen-untracked` (warnings) otherwise.
- Handler metrics: dead selectors, high revert rates, high `vm.assume` discard rates,
  campaigns where every call reverted or no calls were made.
- Respects the Foundry profile: runs, depth, `fail_on_revert`, match filters, custom
  folders, remappings, inline `forge-config:` comments.
- Isolated build in `cache/vacuity/`; your own `out/` and build cache are never touched.
- Text and JSON reports, `--ignore`, `--strict`, `--from-json`, `--no-probe`.
- GitHub Action.
- Supports Forge 1.1.0 to 1.8.6, solc 0.8.0 to 0.8.28, Python 3.9 to 3.13. Tested on Linux.

[0.1.0]: https://github.com/keldxd/invariant-vacuity/releases/tag/v0.1.0
