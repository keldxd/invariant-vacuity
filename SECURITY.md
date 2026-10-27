# Security policy

invariant-vacuity is used to decide whether an invariant suite can be trusted, so a wrong
answer can be a security problem in someone else's audit. Please report these privately.

## What to report privately

- **Missed vacuity (false negative).** A suite where an invariant was clearly never
  exercised (its inputs could not change, or every handler call reverted), but the tool
  reported it as `ok` / `live` with no warning.
- **Anything that makes the tool unsafe to run** on a project you do not fully trust,
  beyond what running `forge build` and `forge test` on that project already implies.
- **Anything that changes files outside** `cache/vacuity/` and the temporary
  `test/__vacuity__/` folder, or leaves the generated probe files behind.

## What can be a normal issue

- A false `frozen` error or a warning you think is wrong. Use the
  "Wrong verdict" issue template. These are bugs, but they do not hide problems.
- Crashes, unsupported setups, documentation mistakes.

## How to report

Use GitHub's private reporting: on this repository, open the **Security** tab and click
**Report a vulnerability**. Please include:

- Forge version (`forge --version`) and invariant-vacuity version (`vacuity --version`)
- The smallest test contract and handler that reproduce it, or a link to a public repo
  and commit
- The command you ran and the full output (`--format json` is most useful)

You will get a reply within 7 days. Confirmed reports are fixed, covered by a new test
fixture so they cannot come back, and credited in the changelog unless you prefer not.

## Supported versions

Only the latest release gets fixes.
