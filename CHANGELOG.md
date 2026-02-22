# Changelog

All notable changes to `kernriftc` are documented in this file.

## v0.2.0 - 2026-02-22

### Added
- Integrated policy gate in `check`:
  - `kernriftc check --policy <policy.toml> <file.kr>`
  - `kernriftc check --policy <policy.toml> --contracts-out <contracts.json> <file.kr>`
- Policy evaluator command:
  - `kernriftc policy --policy <policy.toml> --contracts <contracts.json>`
- Canonical contracts artifact outputs from `check`:
  - `--contracts-out`, `--hash-out`, `--sign-ed25519`, `--sig-out`
- Artifact verification command:
  - `kernriftc verify --contracts <contracts.json> --hash <contracts.sha256> [--sig <contracts.sig> --pubkey <pubkey.hex>]`

### Changed
- Policy diagnostics are now deterministic and code-prefixed:
  - `policy: <CODE>: <message>`
- Policy `max_lock_depth` is evaluated from `report.max_lock_depth`.
- Exit code split is enforced:
  - `0` success
  - `1` policy/verification deny
  - `2` invalid input/config/schema/decode/tooling errors

### Safety Hardening
- Embedded contracts schema is used for validation (distro-safe, no repo path dependency).
- `check` refuses overwriting existing output files.
- Output writes use staged temp files before commit.
- `verify` now requires UTF-8 contracts content and schema/version-valid contracts payload (not only hash/signature match).
