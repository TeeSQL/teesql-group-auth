// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ─────────────────────────────────────────────────────────────────────────────
// DstackKmsSigChainTest
// ─────────────────────────────────────────────────────────────────────────────
//
// Comprehensive test suite for `DstackKmsAdapterFacet._verifySigChain`,
// the dstack 3-level KMS sig-chain verifier dispatched through the diamond
// at the `dstack_kms_verifySigChain(bytes)` selector.
//
// Verifier under test (file:line citations against the `src/` tree):
//   • `src/facets/dstack/DstackKmsAdapterFacet.sol:101-146` — `_verifySigChain`
//   • `src/DstackSigChain.sol:79-103`                       — `recover`
//   • `src/DstackSigChain.sol:85-126`                       — `compressedToAddress`
//   • `src/DstackSigChain.sol:128-135`                      — `_modExp`
//   • `src/storage/KmsDstackStorage.sol`                    — `allowedKmsRoots`
//
// We do NOT enable `ffi`. Instead, we precomputed 10 deterministic
// (privKey, address, compressedPubkey) tuples once via `cast wallet
// public-key --raw-private-key` (each privkey is `0x<digit repeated 64 times>`)
// and embed them as constants. That gives us:
//   • a stable, hermetic test fixture (no network, no shell-out, no fs read);
//   • coverage of BOTH compressed-pubkey y-parity prefixes (0x02 and 0x03);
//   • forge's `vm.sign(privKey, hash)` produces real ECDSA sigs that recover
//     to the addresses in our table — closing the loop end-to-end through
//     the contract's `ecrecover` + EC-math sqrt path.
//
// We inherit from `DiamondSmokeTest` so we reuse `_buildDiamond()`, the
// MockDstackKms, and the bytes32 attestation/KMS ids — the entire smoke
// surface is set up exactly as production callers see it.
//
// ─────────────────────────────────────────────────────────────────────────────

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {DiamondSmokeTest} from "../DiamondSmoke.t.sol";

import {DstackKmsAdapterFacet} from "src/facets/dstack/DstackKmsAdapterFacet.sol";
import {DstackSigChain} from "src/DstackSigChain.sol";
import {IDstackKmsAdapter} from "src/interfaces/IDstackKmsAdapter.sol";
import {IAdmin} from "src/interfaces/IAdmin.sol";
import {KmsDstackStorage} from "src/storage/KmsDstackStorage.sol";

contract DstackKmsSigChainTest is DiamondSmokeTest {
    // ─── Precomputed keypair fixtures ──────────────────────────────────────
    //
    // Generated via:
    //   for pk in 0x111...111 0x222...222 ... ; do
    //     cast wallet address       --private-key "$pk"
    //     cast wallet public-key    --raw-private-key "$pk"
    //   done
    //
    // The `compressedPubkey` is `0x{02|03}{X}` where the prefix encodes
    // y-parity (0x02 = even y, 0x03 = odd y). secp256k1 X coordinate
    // is the leading 32 bytes of the uncompressed pubkey.
    //
    // We picked seeds so the table contains BOTH parities — see the prefix
    // column. Tests that need a specific parity reference the table by
    // index. Tests that don't care just take K1.

    // ─── Index → (privkey, address, compressedPubkey, prefix) table ────────
    // K1: prefix 0x03 (odd y)
    uint256 internal constant PK1 = 0x1111111111111111111111111111111111111111111111111111111111111111;
    address internal constant ADDR1 = 0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A;
    bytes internal constant COMP1 = hex"034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

    // K2: prefix 0x02 (even y)
    uint256 internal constant PK2 = 0x2222222222222222222222222222222222222222222222222222222222222222;
    address internal constant ADDR2 = 0x1563915e194D8CfBA1943570603F7606A3115508;
    bytes internal constant COMP2 = hex"02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";

    // K3: prefix 0x02
    uint256 internal constant PK3 = 0x3333333333333333333333333333333333333333333333333333333333333333;
    address internal constant ADDR3 = 0x5CbDd86a2FA8Dc4bDdd8a8f69dBa48572EeC07FB;
    bytes internal constant COMP3 = hex"023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1";

    // K4: prefix 0x03
    uint256 internal constant PK4 = 0x4444444444444444444444444444444444444444444444444444444444444444;
    address internal constant ADDR4 = 0x7564105E977516C53bE337314c7E53838967bDaC;
    bytes internal constant COMP4 = hex"032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991";

    // K5: prefix 0x02
    uint256 internal constant PK5 = 0x5555555555555555555555555555555555555555555555555555555555555555;
    address internal constant ADDR5 = 0xe1fAE9b4fAB2F5726677ECfA912d96b0B683e6a9;
    bytes internal constant COMP5 = hex"029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b";

    // K6: prefix 0x03
    uint256 internal constant PK6 = 0x6666666666666666666666666666666666666666666666666666666666666666;
    address internal constant ADDR6 = 0xdb2430B4e9AC14be6554d3942822BE74811A1AF9;
    bytes internal constant COMP6 = hex"035ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c30";

    // ─── Domain constants ──────────────────────────────────────────────────
    bytes32 internal constant TEST_MESSAGE_HASH = 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789;
    string internal constant DEFAULT_PURPOSE = "ethereum";

    // Diamond as IDstackKmsAdapter — set up via _ensureKms in each test.
    IDstackKmsAdapter internal kms;

    // ─── Lifecycle ─────────────────────────────────────────────────────────
    //
    // `DiamondSmokeTest.setUp` is NOT virtual, so we can't override it. Each
    // test method calls `_ensureKms()` first; it builds the diamond on first
    // call and is a no-op afterward (idempotent for safety even though forge
    // re-runs setUp per test).

    function _ensureKms() internal {
        if (address(kms) != address(0)) return;
        _buildDiamond();
        kms = IDstackKmsAdapter(address(diamond));
    }

    /// Modifier for every test: lazy-build the diamond + cache the adapter.
    /// Cleaner than sprinkling `_ensureKms();` at the top of each method.
    modifier withKms() {
        _ensureKms();
        _;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section A — Happy path (Tests 1-4)
    // ═══════════════════════════════════════════════════════════════════════

    /// Full valid 4-link proof returns the expected `(codeId, derivedPubkey)`.
    /// Uses K1 (prefix 0x03) as the app key, K2 (prefix 0x02) as the derived key,
    /// and K3 as the KMS root (which we add to the allowlist).
    function test_verifySigChain_happyPath_dstackishProof() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4, // codeId carries an arbitrary app passthrough
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        (bytes32 codeId, bytes memory derivedPubkey) = kms.dstack_kms_verifySigChain(abi.encode(p));

        assertEq(codeId, bytes32(bytes20(ADDR4)), "codeId echoed");
        assertEq(derivedPubkey, COMP2, "derivedPubkey echoed");
    }

    /// codeId echoed verbatim (top-20-bytes app addr, bottom-12 zero).
    function test_verifySigChain_returnsCorrectCodeId() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        address appPassthrough = address(0xcafE000000000000000000000000000000000001);
        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: appPassthrough,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        (bytes32 codeId,) = kms.dstack_kms_verifySigChain(abi.encode(p));
        assertEq(codeId, bytes32(bytes20(appPassthrough)), "codeId == bytes20(appId)");
        // Sanity: bottom 12 bytes are zero.
        assertEq(uint256(codeId) << 160, 0, "lower 12 bytes zero");
    }

    /// derivedPubkey echoed verbatim (33 bytes, prefix preserved).
    function test_verifySigChain_returnsCorrectDerivedPubkey() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        (, bytes memory derivedPubkey) = kms.dstack_kms_verifySigChain(abi.encode(p));
        assertEq(derivedPubkey.length, 33, "33 bytes");
        assertEq(uint8(derivedPubkey[0]), 0x02, "prefix preserved (K2 is 0x02)");
        assertEq(derivedPubkey, COMP2, "byte-for-byte echo");
    }

    /// Both compressed-pubkey prefixes (0x02 and 0x03) round-trip correctly.
    /// Uses K4 (prefix 0x03) as the derived key in one direction and K2
    /// (prefix 0x02) in the other — both must validate end-to-end.
    function test_verifySigChain_acceptsBothCompressedPubkeyPrefixes() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        // Variant A: derived key has prefix 0x03 (K4)
        {
            DstackSigChain.Proof memory pA = _buildProof({
                appPriv: PK1,
                appAddr: ADDR1,
                appComp: COMP1,
                derivedPriv: PK4,
                derivedAddr: ADDR4,
                derivedComp: COMP4,
                kmsPriv: PK3,
                codeIdAppId: ADDR5,
                messageHash: TEST_MESSAGE_HASH,
                purpose: DEFAULT_PURPOSE
            });
            (, bytes memory dA) = kms.dstack_kms_verifySigChain(abi.encode(pA));
            assertEq(uint8(dA[0]), 0x03, "variant A prefix 0x03");
        }

        // Variant B: derived key has prefix 0x02 (K2)
        {
            DstackSigChain.Proof memory pB = _buildProof({
                appPriv: PK1,
                appAddr: ADDR1,
                appComp: COMP1,
                derivedPriv: PK2,
                derivedAddr: ADDR2,
                derivedComp: COMP2,
                kmsPriv: PK3,
                codeIdAppId: ADDR5,
                messageHash: TEST_MESSAGE_HASH,
                purpose: DEFAULT_PURPOSE
            });
            (, bytes memory dB) = kms.dstack_kms_verifySigChain(abi.encode(pB));
            assertEq(uint8(dB[0]), 0x02, "variant B prefix 0x02");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section B — InvalidSigChain branches (Tests 5-11)
    // ═══════════════════════════════════════════════════════════════════════

    /// codeId with non-zero bottom 12 bytes reverts. Mirrors the
    /// `if ((uint256(p.codeId) << 160) != 0) revert InvalidSigChain();`
    /// invariant at DstackKmsAdapterFacet.sol:110.
    function test_verifySigChain_revertsOnNonZeroLowerCodeId() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });
        // Pollute the lower 12 bytes of codeId — bytes20(p.codeId) will still
        // recover the original app addr for the KMS message build, but the
        // lower-12 invariant check fires first on the verify side.
        p.codeId = bytes32(uint256(p.codeId) | 0x00000000000000000000000000000000000000000000000000000000000000ff);

        vm.expectRevert(DstackKmsAdapterFacet.InvalidSigChain.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// appSig recovers to addr X, but appCompressedPubkey corresponds to
    /// addr Y → step-4 mismatch. Verifier line: 141-143.
    function test_verifySigChain_revertsOnAppSigPubkeyMismatch() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        // Build a proof where the app sig is by K1 but we claim K2's pubkey
        // belongs to it. The chain still recovers a valid app EOA (ADDR1)
        // from the sig, but `_compressedPubkeyToAddress(COMP2) == ADDR2`
        // ≠ ADDR1, so step 4 reverts.
        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK4,
            derivedAddr: ADDR4,
            derivedComp: COMP4,
            kmsPriv: PK3,
            codeIdAppId: ADDR5,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        // Tamper: claim K2's pubkey for the app even though sig is by K1.
        // We must rebuild the KMS sig because it covers appCompressedPubkey.
        p.appCompressedPubkey = COMP2;
        p.kmsSignature = _signKms(PK3, p.codeId, p.appCompressedPubkey);

        vm.expectRevert(DstackKmsAdapterFacet.InvalidSigChain.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// kmsSig recovers a signer NOT in `allowedKmsRoots` → step-2 mismatch.
    /// Verifier line: 127.
    function test_verifySigChain_revertsOnKmsRootNotAllowed() public withKms {
        // Allow ADDR5 instead of ADDR3 — the KMS sig will be by K3, which
        // recovers to ADDR3, which is NOT allowed.
        kms.dstack_kms_addRoot(ADDR5);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        vm.expectRevert(DstackKmsAdapterFacet.InvalidSigChain.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// messageSig recovers addr X, but derivedCompressedPubkey corresponds
    /// to addr Y → step-3 mismatch. Verifier line: 135-137.
    function test_verifySigChain_revertsOnDerivedSigPubkeyMismatch() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        // Build with K2 as derived; sig is by K2, sig recovers to ADDR2.
        // Then swap derivedCompressedPubkey to COMP4 (ADDR4) so the address
        // computed from the pubkey diverges from the recovered signer.
        // We must rebuild the app sig because it covers derivedCompressedPubkey
        // (via the "purpose:hex(derivedPubkey)" message). And we must rebuild
        // the KMS sig too — wait, no: the KMS sig covers appCompressedPubkey,
        // not derived. Only the app sig depends on derivedCompressedPubkey.
        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR5,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        // Tamper: replace derived pubkey field with COMP4 (ADDR4) but keep
        // messageSignature signed by PK2 (recovers to ADDR2).
        p.derivedCompressedPubkey = COMP4;
        // Rebuild the app sig over the new derivedHex — otherwise step 1 OR
        // step 4 would catch the mismatch first and we wouldn't isolate the
        // step-3 branch we want to exercise here.
        p.appSignature = _signApp(PK1, DEFAULT_PURPOSE, p.derivedCompressedPubkey);

        vm.expectRevert(DstackKmsAdapterFacet.InvalidSigChain.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// Change `purpose` between sig and verify → recovered app addr differs
    /// from claimed → step 4 reverts. (Step 1 still returns SOME addr, but
    /// it won't match `_compressedPubkeyToAddress(appCompressedPubkey)`.)
    function test_verifySigChain_revertsOnTamperedAppMessage() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });
        // Sig was over "ethereum:<hex>", but we claim purpose = "key" on the
        // verify side — recovered app addr will be a junk address (NOT ADDR1).
        p.purpose = "key";

        vm.expectRevert(DstackKmsAdapterFacet.InvalidSigChain.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// Flip a bit in codeId between kmsSig and proof → recovered KMS signer
    /// is a junk address → not in allowedKmsRoots → step 2 reverts.
    function test_verifySigChain_revertsOnTamperedKmsAppId() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        // Flip a bit in the upper 20 bytes of codeId (so the lower-12-zero
        // invariant still holds — we want to exercise step 2 specifically).
        // bytes20(p.codeId) is the appId the KMS sig was over; mutating it
        // makes the KMS sig recover to a junk address.
        bytes32 corrupted = p.codeId ^ bytes32(uint256(1) << 160);
        // Sanity: lower 12 bytes still zero.
        require(uint256(corrupted) << 160 == 0, "tamper preserves lower-12 zero");
        p.codeId = corrupted;

        vm.expectRevert(DstackKmsAdapterFacet.InvalidSigChain.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// Change `messageHash` between sig and verify → derived sig recovers
    /// junk → step 3 reverts.
    function test_verifySigChain_revertsOnTamperedDerivedMessage() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });
        // Sig was over EIP-191(TEST_MESSAGE_HASH); we claim a different hash
        // on verify — recovered messageSigner ≠ ADDR2.
        p.messageHash = bytes32(uint256(TEST_MESSAGE_HASH) ^ 1);

        vm.expectRevert(DstackKmsAdapterFacet.InvalidSigChain.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section C — BadSignatureLength (Tests 12-14)
    // ═══════════════════════════════════════════════════════════════════════

    /// 64-byte appSignature → BadSignatureLength.
    function test_verifySigChain_revertsOnShortAppSig() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });
        p.appSignature = _truncate(p.appSignature, 64);

        vm.expectRevert(DstackSigChain.BadSignatureLength.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// 64-byte kmsSignature → BadSignatureLength.
    function test_verifySigChain_revertsOnShortKmsSig() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });
        p.kmsSignature = _truncate(p.kmsSignature, 64);

        vm.expectRevert(DstackSigChain.BadSignatureLength.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// 64-byte messageSignature → BadSignatureLength.
    function test_verifySigChain_revertsOnShortMessageSig() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });
        p.messageSignature = _truncate(p.messageSignature, 64);

        vm.expectRevert(DstackSigChain.BadSignatureLength.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section D — BadPubkey (Tests 15-16)
    // ═══════════════════════════════════════════════════════════════════════

    /// 32-byte (not 33) derivedCompressedPubkey → BadPubkey on the
    /// `compressedToAddress` call inside step 3.
    function test_verifySigChain_revertsOnShortDerivedPubkey() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        // Truncate to 32 bytes. NOTE: this also changes step-1's "derivedHex",
        // so step 1's `recoveredApp` will diverge — but step 3 reaches the
        // `_compressedPubkeyToAddress` BEFORE step 4 evaluates, and length=32
        // reverts BadPubkey there. Verifier order in
        // DstackKmsAdapterFacet.sol:131-138 confirms step 3 runs before
        // step 4.
        bytes memory short = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            short[i] = COMP2[i + 1];
        }
        p.derivedCompressedPubkey = short;

        vm.expectRevert(DstackSigChain.BadPubkey.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// derivedCompressedPubkey prefix byte = 0x04 → BadPubkey.
    function test_verifySigChain_revertsOnInvalidPubkeyPrefix() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        // Replace prefix byte with 0x04 (uncompressed marker, invalid here).
        bytes memory bad = bytes.concat(p.derivedCompressedPubkey);
        bad[0] = 0x04;
        p.derivedCompressedPubkey = bad;

        vm.expectRevert(DstackSigChain.BadPubkey.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    /// derivedCompressedPubkey prefix byte = 0x05 → BadPubkey.
    function test_verifySigChain_revertsOnInvalidPubkeyPrefix_0x05() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });
        bytes memory bad = bytes.concat(p.derivedCompressedPubkey);
        bad[0] = 0x05;
        p.derivedCompressedPubkey = bad;

        vm.expectRevert(DstackSigChain.BadPubkey.selector);
        kms.dstack_kms_verifySigChain(abi.encode(p));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section E — Admin paths: root allowlist + KMS pointer (Tests 17-22)
    // ═══════════════════════════════════════════════════════════════════════

    function test_dstack_kms_addRoot_storesAndEmits() public withKms {
        address root = ADDR4;
        // Pre: not allowed.
        assertFalse(kms.dstack_kms_allowedRoots(root), "pre: root not allowed");

        vm.expectEmit(true, false, false, true, address(diamond));
        emit DstackKmsAdapterFacet.KmsRootAdded(root);
        kms.dstack_kms_addRoot(root);

        assertTrue(kms.dstack_kms_allowedRoots(root), "post: root allowed");
    }

    function test_dstack_kms_removeRoot_clearsAndEmits() public withKms {
        address root = ADDR4;
        kms.dstack_kms_addRoot(root);
        assertTrue(kms.dstack_kms_allowedRoots(root), "added");

        vm.expectEmit(true, false, false, true, address(diamond));
        emit DstackKmsAdapterFacet.KmsRootRemoved(root);
        kms.dstack_kms_removeRoot(root);

        assertFalse(kms.dstack_kms_allowedRoots(root), "removed");
    }

    function test_dstack_kms_setKms_storesAndEmits() public withKms {
        address newKms = address(0xBEEF);
        // Pre: kms == deployer (set in DiamondInit by smoke harness).
        assertEq(kms.dstack_kms_kms(), deployer, "pre: deployer");

        vm.expectEmit(true, false, false, true, address(diamond));
        emit DstackKmsAdapterFacet.KmsSet(newKms);
        kms.dstack_kms_setKms(newKms);

        assertEq(kms.dstack_kms_kms(), newKms, "post: rotated");
    }

    function test_dstack_kms_setKms_revertsOnZero() public withKms {
        vm.expectRevert(DstackKmsAdapterFacet.ZeroAddress.selector);
        kms.dstack_kms_setKms(address(0));
    }

    function test_dstack_kms_addRoot_revertsOnZero() public withKms {
        vm.expectRevert(DstackKmsAdapterFacet.ZeroAddress.selector);
        kms.dstack_kms_addRoot(address(0));
    }

    /// Non-owner cannot add a root. The check goes through
    /// `IAdmin(this).requireOwnerOrPassthrough(msg.sender)`, which reads
    /// `OwnableStorage.layout().owner` (set to the test contract by
    /// DiamondInit). Pranking from a different EOA must fail with
    /// IAdmin.NotAuthorized.
    function test_dstack_kms_addRoot_revertsForNonOwner() public withKms {
        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        kms.dstack_kms_addRoot(ADDR4);
    }

    function test_dstack_kms_removeRoot_revertsForNonOwner() public withKms {
        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        kms.dstack_kms_removeRoot(ADDR4);
    }

    function test_dstack_kms_setKms_revertsForNonOwner() public withKms {
        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        kms.dstack_kms_setKms(address(0xBEEF));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section F — Idempotence / state isolation (Tests 23-24)
    // ═══════════════════════════════════════════════════════════════════════

    /// Calling twice returns the same value (no side effects). The verifier
    /// is `view` so this is structurally guaranteed by the type system, but
    /// we assert byte-equality of two consecutive calls anyway as a defensive
    /// regression guard against future non-view rewrites.
    function test_verifySigChain_isPure() public withKms {
        kms.dstack_kms_addRoot(ADDR3);

        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });
        bytes memory blob = abi.encode(p);

        (bytes32 c1, bytes memory d1) = kms.dstack_kms_verifySigChain(blob);
        (bytes32 c2, bytes memory d2) = kms.dstack_kms_verifySigChain(blob);

        assertEq(c1, c2, "codeId stable");
        assertEq(d1, d2, "derivedPubkey stable");
    }

    /// A successful verify call must not mutate KmsDstackStorage. We snapshot
    /// the relevant storage slots before + after and assert equality.
    function test_verifySigChain_doesNotMutateState() public withKms {
        kms.dstack_kms_addRoot(ADDR3);
        DstackSigChain.Proof memory p = _buildProof({
            appPriv: PK1,
            appAddr: ADDR1,
            appComp: COMP1,
            derivedPriv: PK2,
            derivedAddr: ADDR2,
            derivedComp: COMP2,
            kmsPriv: PK3,
            codeIdAppId: ADDR4,
            messageHash: TEST_MESSAGE_HASH,
            purpose: DEFAULT_PURPOSE
        });

        bytes32 slotKms = KmsDstackStorage.SLOT; // .kms
        // allowedKmsRoots is at SLOT + 1, but mappings store entries at
        // keccak(key . slot). We snapshot the literal Layout slots that are
        // value types (the kms address) AND the well-known mapping bucket
        // for ADDR3 to confirm no rewrite slips in.
        bytes32 mappingKey = keccak256(abi.encode(ADDR3, bytes32(uint256(slotKms) + 1)));

        bytes32 kmsBefore = vm.load(address(diamond), slotKms);
        bytes32 rootBefore = vm.load(address(diamond), mappingKey);

        kms.dstack_kms_verifySigChain(abi.encode(p));

        bytes32 kmsAfter = vm.load(address(diamond), slotKms);
        bytes32 rootAfter = vm.load(address(diamond), mappingKey);

        assertEq(kmsBefore, kmsAfter, "kms slot unchanged");
        assertEq(rootBefore, rootAfter, "root allowlist unchanged");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section G — Trivial getters (function-coverage completion)
    // ═══════════════════════════════════════════════════════════════════════

    /// `dstack_kms_id()` returns the pinned `keccak256("teesql.kms.dstack")`
    /// — spec §19.1 / DstackKmsAdapterFacet.sol:23-24.
    function test_dstack_kms_id_returnsPinnedConstant() public withKms {
        bytes32 expected = 0xea3b7f2cbbf5315c63b218799434c030d178fb226a363f7a57c82e25ccff0fd7;
        assertEq(kms.dstack_kms_id(), expected, "kms id");
        // Sanity: matches the live keccak.
        assertEq(expected, keccak256(bytes("teesql.kms.dstack")), "matches keccak");
    }

    /// `dstack_kms_version()` returns 1 — DstackKmsAdapterFacet.sol:88-90.
    function test_dstack_kms_version_returns1() public withKms {
        assertEq(kms.dstack_kms_version(), 1, "version");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ─── Helpers ──────────────────────────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a complete, valid proof. All signatures are computed by signing
    /// with `vm.sign(privKey, hash)` and concatenated as r||s||v (65 bytes,
    /// matching `DstackSigChain._recoverSigner`'s assembly load order).
    function _buildProof(
        uint256 appPriv,
        address appAddr,
        bytes memory appComp,
        uint256 derivedPriv,
        address derivedAddr,
        bytes memory derivedComp,
        uint256 kmsPriv,
        address codeIdAppId,
        bytes32 messageHash,
        string memory purpose
    ) internal pure returns (DstackSigChain.Proof memory p) {
        // Silence unused-arg warnings — these are documentation hooks for
        // the reader (so the call sites read declaratively).
        appAddr;
        derivedAddr;

        p.codeId = bytes32(bytes20(codeIdAppId));
        p.messageHash = messageHash;
        p.derivedCompressedPubkey = derivedComp;
        p.appCompressedPubkey = appComp;
        p.purpose = purpose;

        p.appSignature = _signApp(appPriv, purpose, derivedComp);
        p.kmsSignature = _signKms(kmsPriv, p.codeId, appComp);
        p.messageSignature = _signMessage(derivedPriv, messageHash);
    }

    /// App key signs `keccak256("<purpose>:<derivedHex>")`. Mirrors
    /// DstackKmsAdapterFacet.sol:115-117.
    function _signApp(uint256 priv, string memory purpose, bytes memory derivedComp)
        internal
        pure
        returns (bytes memory)
    {
        string memory derivedHex = _bytesToHex(derivedComp);
        bytes32 hash = keccak256(bytes(abi.encodePacked(purpose, ":", derivedHex)));
        return _sign(priv, hash);
    }

    /// KMS root signs `keccak256("dstack-kms-issued:" || bytes20(appId) || appPubkey)`.
    /// Mirrors DstackKmsAdapterFacet.sol:122-125.
    function _signKms(uint256 priv, bytes32 codeId, bytes memory appComp) internal pure returns (bytes memory) {
        bytes32 hash = keccak256(abi.encodePacked("dstack-kms-issued:", bytes20(codeId), appComp));
        return _sign(priv, hash);
    }

    /// Derived key signs the EIP-191-prefixed messageHash. Mirrors
    /// DstackKmsAdapterFacet.sol:131-134.
    function _signMessage(uint256 priv, bytes32 messageHash) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        return _sign(priv, ethHash);
    }

    /// Sign with `vm.sign` and pack as r||s||v (65 bytes).
    function _sign(uint256 priv, bytes32 hash) internal pure returns (bytes memory) {
        Vm vmCheat = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
        (uint8 v, bytes32 r, bytes32 s) = vmCheat.sign(priv, hash);
        return abi.encodePacked(r, s, v);
    }

    /// Mirror of DstackSigChain._bytesToHex (private in the library).
    function _bytesToHex(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    /// Truncate `b` to `len` bytes.
    function _truncate(bytes memory b, uint256 len) internal pure returns (bytes memory) {
        require(b.length >= len, "_truncate: too short");
        bytes memory out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[i];
        }
        return out;
    }
}
