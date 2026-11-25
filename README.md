![muun](https://muun.com/images/github-banner-v2.png)

## About

This is the source code repository for muun's wallet core library. Muun is a non-custodial 2-of-2 multisig wallet with a special focus on security and ease of use.

This library is used by our mobile wallets with [gomobile](https://godoc.org/golang.org/x/mobile/cmd/gomobile).

## Recovery code versions

| Version | Format | Checksum |
|---|---|---|
| 1 (legacy) | 8 blocks of 4, no `L` prefix | none |
| 2 | `LA..`, 8 blocks of 4 | none |
| 3 | `LB..`, 9 blocks of 4 | block 9: detects every 1- or 2-character error and locates single typos offline |

`GenerateRecoveryCode()` produces version 2 codes. Version 3 is opt-in through `GenerateRecoveryCodeWithVersion(3)`. All versions can be validated with `ValidateRecoveryCode` and converted to a key with `RecoveryCodeToKey`.

The format, checksum and key derivation are specified in [recoverycode/SPEC.md](recoverycode/SPEC.md), with test vectors in [recoverycode/testdata/v3_vectors.json](recoverycode/testdata/v3_vectors.json). Read the spec's integration notes before generating v3 codes for users.

## Responsible Disclosure

Send us an email to report any security related bugs or vulnerabilities at [security@muun.com](mailto:security@muun.com).

You can encrypt your email message using our public PGP key.

Public key fingerprint: `2576 FE1C 2FD3 9DD0 7CAA 3D1D A6F4 476C E444 C8BE`

