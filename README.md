# teesql-group-auth

Solidity contracts for TEE group authorization, KMS boot gating, and cluster
membership/failover. Deployed on Base mainnet as the on-chain control plane
for [TeeSQL](https://github.com/TeeSQL) — a TEE-hosted PostgreSQL
Database-as-a-Service running inside dstack Confidential VMs.

The contracts here do three jobs:

1. **Gate CVM boot** against allowlists of compose hashes, device IDs, and
   KMS root signers (dstack's `IAppAuth` flow).
2. **Register cluster members** using proofs chained from the dstack KMS
   signature hierarchy, so every CVM in a cluster is provably running
   approved code on approved hardware.
3. **Authorize off-chain actions** — signer authorization and leader-lease
   registries that clients and peer CVMs can verify on-chain before trusting
   a given endpoint.

The TEE bridge pieces (`TEEBridge`, `IVerifier`, `DstackVerifier`) are
platform-agnostic and are a hardened fork of
[`Account-Link/tee-interop`](https://github.com/Account-Link/tee-interop)
by [sxysun](https://github.com/sxysun), re-wrapped as UUPS+Ownable proxies
so they can be upgraded under our Safe governance. The `IAppAuth` family
mirrors interfaces from [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack).

## Contracts

| Contract | Role |
|---|---|
| `TeeSqlClusterApp` | Unified cluster controller (UUPS proxy). KMS boot gate, member registry, signer authorization, leader-lease registry. Implements `IAppAuth` + `IAppAuthBasicManagement` + `IKmsRootRegistry`. |
| `TeeSqlClusterMember` | Minimal, immutable per-CVM passthrough. Each CVM gets its own deterministically-deployed `TeeSqlClusterMember` address that forwards `isAppAllowed` to the cluster contract. The CVM's passthrough address is what dstack's `DstackKms` sees as its `app_id`. |
| `TEEBridge` | Platform-agnostic TEE membership registry (UUPS proxy). Holds allowlists of verifiers and code IDs, indexed member records, and an onboarding mailbox. |
| `DstackVerifier` | `IVerifier` implementation for dstack TEEs (UUPS proxy). Holds the `allowedKmsRoots` set and calls into `DstackSigChain` to verify proofs. |
| `DstackSigChain` | Pure library that verifies the dstack 3-level KMS signature chain: **KMS root → app key → derived key → registration message**. |
| `IAppAuth` | Mirrored from dstack (`0x1e079198`). Called by `DstackKms` during CVM boot with `AppBootInfo`. |
| `IAppAuthBasicManagement` | Mirrored from dstack (`0x8fd37527`). Compose-hash / device-id allowlist management. |
| `IVerifier` | Interface every TEE-platform verifier implements so `TEEBridge` can remain platform-agnostic. |

## Deployed addresses (Base mainnet, chain id 8453)

| Name | Address |
|---|---|
| Phala managed `DstackKms` proxy (canonical) | `0x2f83172A49584C017F2B256F0FB2Dca14126Ba9C` |
| `TeeSqlClusterApp` proxy (monitor cluster) | `0xbd32b609057a1a4569558a571d535c8f1212b097` |
| `TEEBridge` proxy | `0x3e0c9ec941b9f93d45e1fb91c5a0782b9089d8ad` |
| `DstackVerifier` proxy | `0xf7a4e66e2054e8cb45fb9e51384c13556ce1c570` |
| Contract owner (Gnosis Safe) | `0xd9f3803a0aFCec138D338aC29e66B2FEdd4edfE3` |

The TeeSQL project does not self-host a `DstackKms` — key custody stays with
Phala's managed KMS. `TeeSqlClusterApp` treats the Phala KMS root signer
(address `0x52d3CF51c8A37A2CCfC79bBb98c7810d7Dd4CE51`, derived from the Phala
k256 root pubkey) as its initial allowed KMS root.

## Boot flow

```
CVM starts
  │
  │ DstackKms.registerApp(appId = TeeSqlClusterMember address)
  ▼
TeeSqlClusterMember.isAppAllowed(bootInfo)
  │
  │ forwards unchanged
  ▼
TeeSqlClusterApp.isAppAllowed(bootInfo)
  │
  ├── composeHash  ∈ allowedComposeHashes ?
  ├── deviceId     ∈ allowedDeviceIds (or allowAnyDevice) ?
  ├── isOurPassthrough[bootInfo.appId] ?
  └── allowedKmsRoots covers the signing chain ?
        │
        ▼
      proceed (or revert with reason)
```

Once booted, each CVM calls `register(RegisterArgs)` on `TeeSqlClusterApp`
with a proof bundle verified by `DstackSigChain.verify(...)`. Accepted
members can then claim leadership, post encrypted endpoints, onboard new
peers, and perform authorized signer-gated actions.

## Build

Requires [Foundry](https://book.getfoundry.sh/).

```shell
forge build
```

Solc 0.8.24, EVM version `cancun`, optimizer runs 200.

## Test

```shell
forge test -vvv
```

CI runs `forge fmt --check`, `forge build --sizes`, and the full test suite
on every push / PR (see `.github/workflows/test.yml`).

## Deploy

`script/Deploy.s.sol` deploys `DstackVerifier` + `TEEBridge` behind
`ERC1967Proxy`. `TeeSqlClusterApp` has its own deploy path in the parent
TeeSQL operator tooling because it depends on additional seed data
(cluster id, initial compose hash, device ids).

Required env vars:

| Var | Purpose |
|---|---|
| `OWNER` | Address to own both proxies (Safe or EOA). |
| `KMS_ROOT` | Initial trusted KMS root signer for `DstackVerifier`. |

Optional:

| Var | Purpose |
|---|---|
| `ALLOWED_CODE_ID` | First compose hash to seed `TEEBridge.allowedCode`. Omit or `0x0` to start empty. |

Example:

```shell
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$BASE_RPC_URL" \
  --private-key "$DEPLOYER_PRIVATE_KEY" \
  --broadcast \
  --verify
```

## Governance

All proxies are `UUPSUpgradeable` + `OwnableUpgradeable` with the owner set
to a Gnosis Safe multisig. Upgrades and admin operations (adding KMS roots,
compose hashes, device ids, signers, verifiers) happen through Safe
transactions, typically generated as Transaction Builder JSON bundles.

`TeeSqlClusterApp` additionally exposes `AccessControlUpgradeable`
(`PAUSER_ROLE`) and `PausableUpgradeable` for operational circuit-breaking
independent of the upgrade path.

> **Storage layout warning.** `TeeSqlClusterApp` has been live through
> multiple upgrades; Member slot 7 and related fields are reserved to
> preserve the pre-v2 layout. Do **not** introduce struct size changes or
> field reorderings without auditing layout drift against the deployed
> proxy — mapping base slots are silently affected by any preceding
> storage change.

## Credits

- TEE bridge architecture ([`TEEBridge`](src/TEEBridge.sol),
  [`IVerifier`](src/IVerifier.sol), and the base of
  [`DstackVerifier`](src/DstackVerifier.sol)) is forked from
  [Account-Link/tee-interop](https://github.com/Account-Link/tee-interop)
  by [sxysun](https://github.com/sxysun).
- [`IAppAuth`](src/IAppAuth.sol) and
  [`IAppAuthBasicManagement`](src/IAppAuthBasicManagement.sol) mirror
  interfaces from [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack).

## License

MIT, except `IAppAuth.sol` and `IAppAuthBasicManagement.sol` which are
Apache-2.0 to match their upstream dstack origin (see per-file SPDX
identifiers).
