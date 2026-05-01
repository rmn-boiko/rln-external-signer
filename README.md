# signer-external

External signer workspace for RLN.

## Crates

- `signer-contract`: shared traits, request/response types, errors.
- `signer-vls-adapter`: VLS-backed backend implementation used by the native UniFFI signer.
- `signer-native-core`: non-VLS/native backend interfaces.
- `signer-testkit`: in-memory deterministic backend for tests.
- `signer-conformance`: shared conformance tests.

## Current Direction

The supported RLN integration path is now a native in-process UniFFI signer.
There is no supported HTTP signer transport in this workspace anymore.
