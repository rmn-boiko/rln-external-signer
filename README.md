# signer-external

Standalone external-signer crate for RGB Lightning Node.

This repository is intended to be consumed directly as a Cargo dependency.

## What it provides

- `contract`
  - request/response types
  - bootstrap payload
  - backend trait
  - signer error types
- `vls_adapter`
  - generic adapter from the stable signer contract to a VLS client
  - `vls_real::RealVlsClient` behind the `with-vls` feature
  - **Holder commitment:** `ChannelOp::ValidateHolderCommitment` maps to **`ValidateCommitmentTx2`** when `commitment_unsigned_tx_hex` is absent or blank; otherwise to **`ValidateCommitmentTx`** (full wire tx + PSBT from `Psbt::from_unsigned_tx`). Protocol errors on the RGB path use the prefix `validate_holder_commitment:rgb_wire_tx:`. Patched **`vls-core`** with **`rgb-commitment-compat`** is required for that branch (see RGB Lightning Node `vendor/vls-core-rgb/UTEXO-RGB-PATCH.md`).
- `native_core`
  - placeholder native backend surface
- `test_utils`
  - test helpers used by this crate

## Features

- default: no VLS backend enabled
- `with-vls`
  - enables the real VLS-backed client implementation

## Cargo usage

Without VLS:

```toml
[dependencies]
signer-external = { git = "https://github.com/UTEXO-Protocol/rln-external-signer", default-features = false }
```

With VLS:

```toml
[dependencies]
signer-external = { git = "https://github.com/UTEXO-Protocol/rln-external-signer", default-features = false, features = ["with-vls"] }
```

## Local checks

```bash
cargo check
cargo test --no-run
cargo check --features with-vls
cargo test --features with-vls --no-run
```
