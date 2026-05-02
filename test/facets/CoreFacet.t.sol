// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {DiamondSmokeTest} from "../DiamondSmoke.t.sol";

import {ICore} from "src/interfaces/ICore.sol";
import {IAdmin} from "src/interfaces/IAdmin.sol";
import {IDstackKmsAdapter} from "src/interfaces/IDstackKmsAdapter.sol";

import {CoreFacet} from "src/facets/CoreFacet.sol";
import {DstackSigChain} from "src/DstackSigChain.sol";
import {CoreStorage} from "src/storage/CoreStorage.sol";

/// @title CoreFacetTest
/// @notice Comprehensive coverage for CoreFacet:
///         - register sig-chain dispatch + binding-sig invariants
///         - claimLeader witness flow (first/self-reclaim/replacement, all reverts)
///         - per-call auth replay protection + retired/destroyed gates
///         - onboarding mailbox semantics (FIFO accumulation)
///         - lifecycle gates (Paused / ClusterDestroyed_)
///         - predictMember CREATE2-binding invariants
///         - registration/call/witness message-helper replay-binding
///
/// @dev    Inherits DiamondSmokeTest to reuse setUp + _buildDiamond +
///         MockDstackKms. The smoke test's setUp is NOT virtual, so we
///         lazy-build the diamond in each test via _ensureDiamond() —
///         pattern mirrored from test/dstack/DstackKmsSigChain.t.sol.
///
///         Sig-chain proofs are constructed in-test using a small pool
///         of deterministic secp256k1 keypairs whose compressed pubkeys
///         are precomputed (cast wallet public-key) and embedded as
///         constants. Per the task brief, this proof-construction
///         harness is duplicated in this file rather than imported from
///         the dstack-sigchain test suite — avoids cross-file
///         coordination, duplication is intentional.
///
///         Compressed pubkey format: prefix byte 0x02 (Y even) or 0x03
///         (Y odd) || X (32 bytes) — DstackSigChain's modexp-based
///         decompression reconstructs the EOA from the prefix's parity.
contract CoreFacetTest is DiamondSmokeTest {
    Vm internal _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // ─── Precomputed keypair fixtures ──────────────────────────────────────
    //
    // Generated outside the test via:
    //   pk=0x<repeated digit×64>; cast wallet address --private-key $pk
    //   cast wallet public-key   --raw-private-key $pk
    //   compressed = (Y even ? 0x02 : 0x03) || X
    //
    // K1: prefix 0x03 (odd y)
    uint256 internal constant PK1 =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    address internal constant ADDR1 = 0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A;
    bytes internal constant COMP1 =
        hex"034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

    // K2: prefix 0x02 (even y)
    uint256 internal constant PK2 =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    address internal constant ADDR2 = 0x1563915e194D8CfBA1943570603F7606A3115508;
    bytes internal constant COMP2 =
        hex"02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";

    // K3: prefix 0x02 -> KMS root (added to allowedKmsRoots in _ensureDiamond)
    uint256 internal constant PK3 =
        0x3333333333333333333333333333333333333333333333333333333333333333;
    address internal constant ADDR3 = 0x5CbDd86a2FA8Dc4bDdd8a8f69dBa48572EeC07FB;
    bytes internal constant COMP3 =
        hex"023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1";

    // K4: prefix 0x03
    uint256 internal constant PK4 =
        0x4444444444444444444444444444444444444444444444444444444444444444;
    address internal constant ADDR4 = 0x7564105E977516C53bE337314c7E53838967bDaC;
    bytes internal constant COMP4 =
        hex"032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991";

    // K5: prefix 0x02
    uint256 internal constant PK5 =
        0x5555555555555555555555555555555555555555555555555555555555555555;
    address internal constant ADDR5 = 0xe1fAE9b4fAB2F5726677ECfA912d96b0B683e6a9;
    bytes internal constant COMP5 =
        hex"029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b";

    // K6: prefix 0x03
    uint256 internal constant PK6 =
        0x6666666666666666666666666666666666666666666666666666666666666666;
    address internal constant ADDR6 = 0xdb2430B4e9AC14be6554d3942822BE74811A1AF9;
    bytes internal constant COMP6 =
        hex"035ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c30";

    // K7: spare — used as an off-registry signer for BadSig scenarios.
    //     pk = 0x77...77 (64 chars).
    uint256 internal constant PK7 =
        0x7777777777777777777777777777777777777777777777777777777777777777;
    address internal constant ADDR7 = 0xAe72A48c1a36bd18Af168541c53037965d26e4A8;

    // K8: prefix 0x02 (spare derived for member 4)
    uint256 internal constant PK8 =
        0x8888888888888888888888888888888888888888888888888888888888888888;
    address internal constant ADDR8 = 0x62f94E9AC9349BCCC61Bfe66ddAdE6292702EcB6;
    bytes internal constant COMP8 =
        hex"021617d38ed8d8657da4d4761e8057bc396ea9e4b9d29776d4be096016dbd2509b";

    string internal constant _PURPOSE = "test-purpose";

    // Diamond is built lazily; first test method to call _ensureDiamond()
    // pays the bring-up cost.
    bool internal _diamondReady;

    function _ensureDiamond() internal {
        if (_diamondReady) return;
        _buildDiamond();
        IDstackKmsAdapter(address(diamond)).dstack_kms_setKms(address(mockKms));
        // The smoke setup wires `deployer` (a contract addr) as the only
        // allowedKmsRoot — we can't sign with that. Add a real keypair
        // root we control.
        IDstackKmsAdapter(address(diamond)).dstack_kms_addRoot(ADDR3);
        _diamondReady = true;
    }

    modifier withDiamond() {
        _ensureDiamond();
        _;
    }

    // ─── Member minting helper ─────────────────────────────────────────────

    struct MemberKeys {
        address passthrough;
        bytes32 memberId;
        // app key (signs "purpose:derivedHex")
        uint256 appPriv;
        bytes appPub;
        // derived key (signs messageHash + all CallAuth blobs)
        uint256 derivedPriv;
        bytes derivedPub;
        address derivedAddr;
        // bound metadata
        address instanceId;
        bytes endpoint;
        bytes publicEndpoint;
        string dnsLabel;
    }

    /// @notice Mint and register a member. `slot` is 1..3 — selects an
    ///         (app, derived) pair from the keypair pool. (slot 4 also
    ///         supported via K7 / K8 for tests that need a 4th member.)
    function _mintMember(uint8 slot) internal returns (MemberKeys memory mk) {
        require(slot >= 1 && slot <= 4, "slot out of range");

        // Slot -> (app key, derived key) assignments. Avoids overlap with
        // K3 (KMS root) and K7 (off-registry sig).
        if (slot == 1) {
            mk.appPriv = PK1; mk.appPub = COMP1;
            mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        } else if (slot == 2) {
            mk.appPriv = PK4; mk.appPub = COMP4;
            mk.derivedPriv = PK5; mk.derivedPub = COMP5; mk.derivedAddr = ADDR5;
        } else if (slot == 3) {
            mk.appPriv = PK1; mk.appPub = COMP1;
            mk.derivedPriv = PK6; mk.derivedPub = COMP6; mk.derivedAddr = ADDR6;
        } else {
            mk.appPriv = PK1; mk.appPub = COMP1;
            mk.derivedPriv = PK8; mk.derivedPub = COMP8; mk.derivedAddr = ADDR8;
        }

        // Mint passthrough.
        bytes32 salt = bytes32(uint256(slot) * 1e18);
        mk.passthrough = ICore(address(diamond)).createMember(
            salt, DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );

        mk.instanceId = address(uint160(uint256(keccak256(abi.encode("instance", slot)))));
        mk.endpoint = abi.encodePacked("endpoint-", slot);
        mk.publicEndpoint = abi.encodePacked("https://m", slot, ".example.com");
        mk.dnsLabel = string(abi.encodePacked("dns-", _slotToString(slot)));

        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);
        mk.memberId = ICore(address(diamond)).register(args);
    }

    /// @notice Build a valid sig-chain proof + binding sig for `mk`.
    ///         Mirrors DstackKmsAdapterFacet._verifySigChain shape:
    ///           Step 1: app key signs "<purpose>:<derivedHex>"
    ///           Step 2: KMS root signs "dstack-kms-issued:" || appId(20) || appPub
    ///           Step 3: derived key signs messageHash (EIP-191)
    ///         The bindingSig is an independent EIP-191 sig over
    ///         registrationMessage(...) by the derived key — its job is
    ///         to prove the derived key consents to *this specific*
    ///         (instanceId, endpoint, publicEndpoint, dnsLabel) tuple.
    function _buildRegisterArgs(MemberKeys memory mk)
        internal
        view
        returns (ICore.RegisterArgs memory args)
    {
        DstackSigChain.Proof memory p;
        p.codeId = bytes32(bytes20(mk.passthrough));
        p.appCompressedPubkey = mk.appPub;
        p.derivedCompressedPubkey = mk.derivedPub;
        p.purpose = _PURPOSE;

        // Step 1: app sig over "purpose:derivedHex"
        p.appSignature = _signApp(mk.appPriv, _PURPOSE, mk.derivedPub);

        // Step 2: KMS root sig
        p.kmsSignature = _signKms(PK3, p.codeId, mk.appPub);

        // Step 3: derived sig over messageHash (EIP-191).
        // The proof's messageHash can be any 32-byte value — the verifier
        // only checks that the derived key signed it. We pick the
        // registration bind hash so the SAME signature blob doubles as
        // bindingSig. Two birds, one ecrecover.
        bytes32 bindHash = ICore(address(diamond)).registrationMessage(
            mk.instanceId, mk.endpoint, mk.publicEndpoint, mk.dnsLabel
        );
        p.messageHash = bindHash;
        bytes memory derivedSig = _signMessage(mk.derivedPriv, bindHash);
        p.messageSignature = derivedSig;
        args.bindingSig = derivedSig;

        args.proof = abi.encode(p);
        args.instanceId = mk.instanceId;
        args.endpoint = mk.endpoint;
        args.publicEndpoint = mk.publicEndpoint;
        args.dnsLabel = mk.dnsLabel;
    }

    function _slotToString(uint8 slot) internal pure returns (string memory) {
        if (slot == 1) return "1";
        if (slot == 2) return "2";
        if (slot == 3) return "3";
        if (slot == 4) return "4";
        return "?";
    }

    // ─── Sig helpers ───────────────────────────────────────────────────────

    function _signApp(uint256 priv, string memory purpose, bytes memory derivedComp)
        internal
        view
        returns (bytes memory)
    {
        string memory derivedHex = _bytesToHex(derivedComp);
        bytes32 hash = keccak256(bytes(abi.encodePacked(purpose, ":", derivedHex)));
        return _sign(priv, hash);
    }

    function _signKms(uint256 priv, bytes32 codeId, bytes memory appComp)
        internal
        view
        returns (bytes memory)
    {
        bytes32 hash = keccak256(
            abi.encodePacked("dstack-kms-issued:", bytes20(codeId), appComp)
        );
        return _sign(priv, hash);
    }

    function _signMessage(uint256 priv, bytes32 messageHash)
        internal
        view
        returns (bytes memory)
    {
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        return _sign(priv, ethHash);
    }

    function _sign(uint256 priv, bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = _vm.sign(priv, hash);
        return abi.encodePacked(r, s, v);
    }

    function _bytesToHex(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    // ─── CallAuth + Witness signing helpers ────────────────────────────────

    function _signCall(
        bytes32 memberId,
        uint256 derivedPriv,
        bytes4 selector,
        bytes memory argBlob
    ) internal view returns (ICore.CallAuth memory auth) {
        uint256 nonce = ICore(address(diamond)).memberNonce(memberId);
        bytes32 callHash = ICore(address(diamond)).callMessage(memberId, nonce, selector, argBlob);
        auth.memberId = memberId;
        auth.nonce = nonce;
        auth.sig = _signMessage(derivedPriv, callHash);
    }

    function _signWitness(
        bytes32 deposedMemberId,
        uint256 deposedEpoch,
        bytes32 voucherMemberId,
        uint256 voucherDerivedPriv
    ) internal view returns (ICore.Witness memory w) {
        bytes32 wHash = ICore(address(diamond)).witnessMessage(
            deposedMemberId, deposedEpoch, voucherMemberId
        );
        w.voucherMemberId = voucherMemberId;
        w.sig = _signMessage(voucherDerivedPriv, wHash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TESTS — register
    // ═══════════════════════════════════════════════════════════════════════

    function test_register_happyPath() public withDiamond {
        // Mint passthrough, then register.
        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1e18)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );

        MemberKeys memory mk;
        mk.passthrough = passthrough;
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"deadbeef";
        mk.publicEndpoint = bytes("https://m1.example.com");
        mk.dnsLabel = "dns-1";

        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);
        bytes32 memberId = ICore(address(diamond)).register(args);

        assertEq(memberId, keccak256(mk.derivedPub), "memberId == keccak(derivedPub)");
        CoreStorage.Member memory m = ICore(address(diamond)).getMember(memberId);
        assertEq(m.instanceId, mk.instanceId, "instanceId");
        assertEq(m.derivedAddr, mk.derivedAddr, "derivedAddr");
        assertEq(m.passthrough, passthrough, "passthrough");
        assertEq(m.dnsLabel, mk.dnsLabel, "dnsLabel");
        assertGt(m.registeredAt, 0, "registeredAt nonzero");
    }

    function test_register_writesAllMappings() public withDiamond {
        MemberKeys memory mk = _mintMember(1);
        assertEq(ICore(address(diamond)).instanceToMember(mk.instanceId), mk.memberId, "instance");
        assertEq(ICore(address(diamond)).derivedToMember(mk.derivedAddr), mk.memberId, "derived");
        assertEq(ICore(address(diamond)).passthroughToMember(mk.passthrough), mk.memberId, "passthrough");
    }

    function test_register_revertsOnWrongAppId() public withDiamond {
        MemberKeys memory mk;
        mk.passthrough = address(0x1234567890123456789012345678901234567890); // never minted
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"aa";
        mk.publicEndpoint = bytes("p");
        mk.dnsLabel = "dns";

        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);
        vm.expectRevert(ICore.WrongAppId.selector);
        ICore(address(diamond)).register(args);
    }

    function test_register_revertsOnInstanceBindingInvalid() public withDiamond {
        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1e18)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );
        MemberKeys memory mk;
        mk.passthrough = passthrough;
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"aa";
        mk.publicEndpoint = bytes("p");
        mk.dnsLabel = "dns";

        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);
        // Replace bindingSig with a sig from the WRONG key (PK7).
        bytes32 bindHash = ICore(address(diamond)).registrationMessage(
            mk.instanceId, mk.endpoint, mk.publicEndpoint, mk.dnsLabel
        );
        args.bindingSig = _signMessage(PK7, bindHash);

        vm.expectRevert(ICore.InstanceBindingInvalid.selector);
        ICore(address(diamond)).register(args);
    }

    function test_register_revertsOnTamperedEndpoint() public withDiamond {
        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1e18)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );
        MemberKeys memory mk;
        mk.passthrough = passthrough;
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"aa"; // signed over this
        mk.publicEndpoint = bytes("p");
        mk.dnsLabel = "dns";

        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);
        args.endpoint = hex"bb"; // submit with a different endpoint

        vm.expectRevert(ICore.InstanceBindingInvalid.selector);
        ICore(address(diamond)).register(args);
    }

    function test_register_revertsOnTamperedDnsLabel() public withDiamond {
        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1e18)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );
        MemberKeys memory mk;
        mk.passthrough = passthrough;
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"aa";
        mk.publicEndpoint = bytes("p");
        mk.dnsLabel = "dns-original";

        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);
        args.dnsLabel = "dns-tampered";

        vm.expectRevert(ICore.InstanceBindingInvalid.selector);
        ICore(address(diamond)).register(args);
    }

    function test_register_revertsOnTamperedInstanceId() public withDiamond {
        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1e18)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );
        MemberKeys memory mk;
        mk.passthrough = passthrough;
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"aa";
        mk.publicEndpoint = bytes("p");
        mk.dnsLabel = "dns";

        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);
        args.instanceId = address(0xCAFE);

        vm.expectRevert(ICore.InstanceBindingInvalid.selector);
        ICore(address(diamond)).register(args);
    }

    function test_register_revertsOnAdapterMismatch() public withDiamond {
        // Stomp the AdapterRegistry.passthroughToKmsId mapping for the
        // minted passthrough so the post-verifySigChain check fails.
        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1e18)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );

        // AdapterRegistryStorage.SLOT = 0x6ee2bb1ae478bac7e8c2d1f0e58e1f7a1636fb53a7bc4fcbf96fa7b68f3afb00
        // Layout offsets:
        //   [0] mapping(address => bytes32) passthroughToAttestationId
        //   [1] mapping(address => bytes32) passthroughToKmsId  ← target
        bytes32 baseSlot = 0x6ee2bb1ae478bac7e8c2d1f0e58e1f7a1636fb53a7bc4fcbf96fa7b68f3afb00;
        bytes32 kmsMappingSlot = bytes32(uint256(baseSlot) + 1);
        bytes32 mappingKey = keccak256(abi.encode(passthrough, kmsMappingSlot));
        // Sanity: precondition — initial value should be DSTACK_KMS_ID.
        bytes32 pre = vm.load(address(diamond), mappingKey);
        assertEq(pre, DSTACK_KMS_ID, "precondition: passthroughToKmsId == dstack");
        vm.store(address(diamond), mappingKey, bytes32(uint256(0xdead)));

        MemberKeys memory mk;
        mk.passthrough = passthrough;
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"aa";
        mk.publicEndpoint = bytes("p");
        mk.dnsLabel = "dns";

        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);
        vm.expectRevert(ICore.WrongAppId.selector);
        ICore(address(diamond)).register(args);
    }

    function test_register_revertsOnDestroyedCluster() public withDiamond {
        IAdmin(address(diamond)).destroy();

        MemberKeys memory mk;
        mk.passthrough = address(0x1234); // unreachable — gate fires first
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"aa";
        mk.publicEndpoint = bytes("p");
        mk.dnsLabel = "dns";
        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);

        vm.expectRevert(ICore.ClusterDestroyed_.selector);
        ICore(address(diamond)).register(args);
    }

    function test_register_revertsOnPaused() public withDiamond {
        IAdmin(address(diamond)).pause();

        MemberKeys memory mk;
        mk.passthrough = address(0x1234);
        mk.appPriv = PK1; mk.appPub = COMP1;
        mk.derivedPriv = PK2; mk.derivedPub = COMP2; mk.derivedAddr = ADDR2;
        mk.instanceId = address(0xBEEF);
        mk.endpoint = hex"aa";
        mk.publicEndpoint = bytes("p");
        mk.dnsLabel = "dns";
        ICore.RegisterArgs memory args = _buildRegisterArgs(mk);

        vm.expectRevert(CoreFacet.Paused.selector);
        ICore(address(diamond)).register(args);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TESTS — claimLeader (witness flow)
    // ═══════════════════════════════════════════════════════════════════════

    function test_claimLeader_firstClaim_noWitnessesRequired() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes memory newEndpoint = bytes("leader-ep");
        ICore.Witness[] memory witnesses = new ICore.Witness[](0);

        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.claimLeader.selector, abi.encode(newEndpoint, witnesses)
        );
        ICore(address(diamond)).claimLeader(auth, newEndpoint, witnesses);

        (bytes32 leader, uint256 epoch) = ICore(address(diamond)).leaderLease();
        assertEq(leader, a.memberId, "leader is A");
        assertEq(epoch, 1, "epoch=1");
    }

    function test_claimLeader_selfReclaim_noWitnessesRequired() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        // First claim
        {
            bytes memory ep = bytes("ep1");
            ICore.Witness[] memory w = new ICore.Witness[](0);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }
        // Self-reclaim with empty witnesses
        bytes memory ep2 = bytes("ep2");
        ICore.Witness[] memory w2 = new ICore.Witness[](0);
        ICore.CallAuth memory auth2 = _signCall(
            a.memberId, a.derivedPriv,
            ICore.claimLeader.selector, abi.encode(ep2, w2)
        );
        ICore(address(diamond)).claimLeader(auth2, ep2, w2);

        (bytes32 leader, uint256 epoch) = ICore(address(diamond)).leaderLease();
        assertEq(leader, a.memberId, "leader still A");
        assertEq(epoch, 2, "epoch=2");
    }

    function test_claimLeader_replacementWithWitness_succeeds() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);
        MemberKeys memory c = _mintMember(3);

        // A claims first (epoch becomes 1).
        {
            bytes memory ep = bytes("ep-a");
            ICore.Witness[] memory w = new ICore.Witness[](0);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }

        // B claims with C's witness sig (over deposed=A, currentEpoch=1, voucher=C).
        bytes memory bEp = bytes("ep-b");
        ICore.Witness[] memory bWitnesses = new ICore.Witness[](1);
        bWitnesses[0] = _signWitness(a.memberId, 1, c.memberId, c.derivedPriv);

        ICore.CallAuth memory bAuth = _signCall(
            b.memberId, b.derivedPriv,
            ICore.claimLeader.selector, abi.encode(bEp, bWitnesses)
        );
        ICore(address(diamond)).claimLeader(bAuth, bEp, bWitnesses);

        (bytes32 leader, uint256 epoch) = ICore(address(diamond)).leaderLease();
        assertEq(leader, b.memberId, "leader is B");
        assertEq(epoch, 2, "epoch=2");
    }

    function test_claimLeader_revertsOnNoWitness() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);

        // A claims first.
        {
            bytes memory ep = bytes("ep-a");
            ICore.Witness[] memory w = new ICore.Witness[](0);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }

        // B claims with EMPTY witnesses -> NoWitness.
        bytes memory bEp = bytes("ep-b");
        ICore.Witness[] memory bWitnesses = new ICore.Witness[](0);
        ICore.CallAuth memory bAuth = _signCall(
            b.memberId, b.derivedPriv,
            ICore.claimLeader.selector, abi.encode(bEp, bWitnesses)
        );

        vm.expectRevert(ICore.NoWitness.selector);
        ICore(address(diamond)).claimLeader(bAuth, bEp, bWitnesses);
    }

    function test_claimLeader_revertsOnSelfWitness() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);

        // A claims first.
        {
            bytes memory ep = bytes("ep-a");
            ICore.Witness[] memory w = new ICore.Witness[](0);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }

        // B uses B's OWN witness sig.
        bytes memory bEp = bytes("ep-b");
        ICore.Witness[] memory bWitnesses = new ICore.Witness[](1);
        bWitnesses[0] = _signWitness(a.memberId, 1, b.memberId, b.derivedPriv);
        ICore.CallAuth memory bAuth = _signCall(
            b.memberId, b.derivedPriv,
            ICore.claimLeader.selector, abi.encode(bEp, bWitnesses)
        );

        vm.expectRevert(ICore.SelfWitness.selector);
        ICore(address(diamond)).claimLeader(bAuth, bEp, bWitnesses);
    }

    function test_claimLeader_revertsOnUnknownWitness() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);

        // A claims first.
        {
            bytes memory ep = bytes("ep-a");
            ICore.Witness[] memory w = new ICore.Witness[](0);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }

        bytes memory bEp = bytes("ep-b");
        bytes32 unknownId = keccak256("unknown");
        ICore.Witness[] memory bWitnesses = new ICore.Witness[](1);
        // Sig key doesn't matter — registry-membership check fires first.
        bWitnesses[0] = _signWitness(a.memberId, 1, unknownId, PK7);
        ICore.CallAuth memory bAuth = _signCall(
            b.memberId, b.derivedPriv,
            ICore.claimLeader.selector, abi.encode(bEp, bWitnesses)
        );

        vm.expectRevert(ICore.WitnessNotMember.selector);
        ICore(address(diamond)).claimLeader(bAuth, bEp, bWitnesses);
    }

    function test_claimLeader_revertsOnDuplicateWitness() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);
        MemberKeys memory c = _mintMember(3);

        // A claims first.
        {
            bytes memory ep = bytes("ep-a");
            ICore.Witness[] memory w = new ICore.Witness[](0);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }

        bytes memory bEp = bytes("ep-b");
        ICore.Witness[] memory bWitnesses = new ICore.Witness[](2);
        bWitnesses[0] = _signWitness(a.memberId, 1, c.memberId, c.derivedPriv);
        bWitnesses[1] = _signWitness(a.memberId, 1, c.memberId, c.derivedPriv);
        ICore.CallAuth memory bAuth = _signCall(
            b.memberId, b.derivedPriv,
            ICore.claimLeader.selector, abi.encode(bEp, bWitnesses)
        );

        vm.expectRevert(ICore.DuplicateWitness.selector);
        ICore(address(diamond)).claimLeader(bAuth, bEp, bWitnesses);
    }

    function test_claimLeader_revertsOnBadWitnessSig() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);
        MemberKeys memory c = _mintMember(3);

        // A claims first.
        {
            bytes memory ep = bytes("ep-a");
            ICore.Witness[] memory w = new ICore.Witness[](0);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }

        bytes memory bEp = bytes("ep-b");
        // Witness *names* C as voucher but is signed by spare PK7.
        // Recovered signer != C.derivedAddr -> BadWitnessSig.
        ICore.Witness[] memory bWitnesses = new ICore.Witness[](1);
        bWitnesses[0] = _signWitness(a.memberId, 1, c.memberId, PK7);
        ICore.CallAuth memory bAuth = _signCall(
            b.memberId, b.derivedPriv,
            ICore.claimLeader.selector, abi.encode(bEp, bWitnesses)
        );

        vm.expectRevert(ICore.BadWitnessSig.selector);
        ICore(address(diamond)).claimLeader(bAuth, bEp, bWitnesses);
    }

    function test_claimLeader_witnessMessageBindsToCurrentEpoch() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);
        MemberKeys memory c = _mintMember(3);

        // A claims -> epoch 1.
        {
            bytes memory ep = bytes("ep-a");
            ICore.Witness[] memory w = new ICore.Witness[](0);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }
        // B claims with C's witness -> epoch 2. (Now leader=B, epoch=2)
        {
            bytes memory ep = bytes("ep-b");
            ICore.Witness[] memory w = new ICore.Witness[](1);
            w[0] = _signWitness(a.memberId, 1, c.memberId, c.derivedPriv);
            ICore.CallAuth memory auth = _signCall(
                b.memberId, b.derivedPriv,
                ICore.claimLeader.selector, abi.encode(ep, w)
            );
            ICore(address(diamond)).claimLeader(auth, ep, w);
        }

        // A wants leader back with a STALE witness (signed for the prior
        // (deposed=A, epoch=1) state — but cluster state is now
        // (deposed=B, epoch=2)). The stale witness's hash differs, so
        // recovered signer != C -> BadWitnessSig.
        bytes memory aEp2 = bytes("ep-a2");
        ICore.Witness[] memory aWitnesses = new ICore.Witness[](1);
        aWitnesses[0] = _signWitness(a.memberId, 1, c.memberId, c.derivedPriv);
        ICore.CallAuth memory aAuth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.claimLeader.selector, abi.encode(aEp2, aWitnesses)
        );

        vm.expectRevert(ICore.BadWitnessSig.selector);
        ICore(address(diamond)).claimLeader(aAuth, aEp2, aWitnesses);
    }

    function test_claimLeader_writesNewEndpoint() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes memory newEp = bytes("brand-new-endpoint");
        ICore.Witness[] memory w = new ICore.Witness[](0);
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.claimLeader.selector, abi.encode(newEp, w)
        );
        ICore(address(diamond)).claimLeader(auth, newEp, w);

        CoreStorage.Member memory m = ICore(address(diamond)).getMember(a.memberId);
        assertEq(keccak256(m.endpoint), keccak256(newEp), "endpoint stored");
    }

    function test_claimLeader_emitsLeaderClaimedEvent() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes memory newEp = bytes("evt-ep");
        ICore.Witness[] memory w = new ICore.Witness[](0);
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.claimLeader.selector, abi.encode(newEp, w)
        );

        vm.expectEmit(true, true, false, true);
        emit ICore.LeaderClaimed(a.memberId, 1, newEp);
        ICore(address(diamond)).claimLeader(auth, newEp, w);
    }

    function test_claimLeader_revertsOnDestroyedCluster() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        IAdmin(address(diamond)).destroy();

        bytes memory ep = bytes("ep");
        ICore.Witness[] memory w = new ICore.Witness[](0);
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.claimLeader.selector, abi.encode(ep, w)
        );
        vm.expectRevert(ICore.ClusterDestroyed_.selector);
        ICore(address(diamond)).claimLeader(auth, ep, w);
    }

    function test_claimLeader_revertsOnPaused() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        IAdmin(address(diamond)).pause();

        bytes memory ep = bytes("ep");
        ICore.Witness[] memory w = new ICore.Witness[](0);
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.claimLeader.selector, abi.encode(ep, w)
        );
        vm.expectRevert(CoreFacet.Paused.selector);
        ICore(address(diamond)).claimLeader(auth, ep, w);
    }

    function test_claimLeader_revertsOnRetiredMember() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        // a is not yet leader, so retire is allowed.
        IAdmin(address(diamond)).retireMember(a.memberId);

        bytes memory ep = bytes("ep");
        ICore.Witness[] memory w = new ICore.Witness[](0);
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.claimLeader.selector, abi.encode(ep, w)
        );
        vm.expectRevert(ICore.MemberRetired_.selector);
        ICore(address(diamond)).claimLeader(auth, ep, w);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TESTS — updateEndpoint / updatePublicEndpoint
    // ═══════════════════════════════════════════════════════════════════════

    function test_updateEndpoint_happyPath() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes memory newEp = bytes("updated-ep");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.updateEndpoint.selector, abi.encode(newEp)
        );

        vm.expectEmit(true, false, false, true);
        emit ICore.EndpointUpdated(a.memberId, newEp);
        ICore(address(diamond)).updateEndpoint(auth, newEp);

        CoreStorage.Member memory m = ICore(address(diamond)).getMember(a.memberId);
        assertEq(keccak256(m.endpoint), keccak256(newEp));
    }

    function test_updateEndpoint_revertsOnBadNonce() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes memory newEp = bytes("ep");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.updateEndpoint.selector, abi.encode(newEp)
        );
        auth.nonce = 999;

        vm.expectRevert(ICore.BadNonce.selector);
        ICore(address(diamond)).updateEndpoint(auth, newEp);
    }

    function test_updateEndpoint_revertsOnBadSig() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes memory newEp = bytes("ep");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.updateEndpoint.selector, abi.encode(newEp)
        );
        // Re-sign with the WRONG key.
        bytes32 callHash = ICore(address(diamond)).callMessage(
            a.memberId, auth.nonce,
            ICore.updateEndpoint.selector, abi.encode(newEp)
        );
        auth.sig = _signMessage(PK7, callHash);

        vm.expectRevert(ICore.BadSig.selector);
        ICore(address(diamond)).updateEndpoint(auth, newEp);
    }

    function test_updateEndpoint_revertsOnRetiredMember() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        IAdmin(address(diamond)).retireMember(a.memberId);

        bytes memory newEp = bytes("ep");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.updateEndpoint.selector, abi.encode(newEp)
        );
        vm.expectRevert(ICore.MemberRetired_.selector);
        ICore(address(diamond)).updateEndpoint(auth, newEp);
    }

    function test_updateEndpoint_revertsOnNonExistentMember() public withDiamond {
        bytes memory newEp = bytes("ep");
        ICore.CallAuth memory auth;
        auth.memberId = bytes32(uint256(0xdeadbeef));
        auth.nonce = 0;
        // Sig content doesn't matter — NotMember check (registeredAt==0)
        // fires before sig recovery. 65 zero bytes is the right length.
        auth.sig = new bytes(65);

        vm.expectRevert(ICore.NotMember.selector);
        ICore(address(diamond)).updateEndpoint(auth, newEp);
    }

    function test_updatePublicEndpoint_happyPath() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes memory newPub = bytes("https://new.example.com");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.updatePublicEndpoint.selector, abi.encode(newPub)
        );

        vm.expectEmit(true, false, false, true);
        emit ICore.PublicEndpointUpdated(a.memberId, newPub);
        ICore(address(diamond)).updatePublicEndpoint(auth, newPub);

        CoreStorage.Member memory m = ICore(address(diamond)).getMember(a.memberId);
        assertEq(keccak256(m.publicEndpoint), keccak256(newPub));
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TESTS — onboard
    // ═══════════════════════════════════════════════════════════════════════

    function test_onboard_happyPath() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);
        bytes memory payload = bytes("encrypted-payload-blob");

        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.onboard.selector, abi.encode(b.memberId, payload)
        );

        vm.expectEmit(true, true, false, true);
        emit ICore.OnboardingPosted(b.memberId, a.memberId);
        ICore(address(diamond)).onboard(auth, b.memberId, payload);

        CoreStorage.OnboardMsg[] memory mailbox = ICore(address(diamond)).getOnboarding(b.memberId);
        assertEq(mailbox.length, 1, "1 message");
        assertEq(mailbox[0].fromMember, a.memberId, "from A");
        assertEq(keccak256(mailbox[0].encryptedPayload), keccak256(payload), "payload");
    }

    function test_onboard_revertsIfTargetUnknown() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes32 unknownId = keccak256("never-existed");
        bytes memory payload = bytes("p");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.onboard.selector, abi.encode(unknownId, payload)
        );

        vm.expectRevert(ICore.NotMember.selector);
        ICore(address(diamond)).onboard(auth, unknownId, payload);
    }

    function test_onboard_revertsOnDestroyed() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);
        bytes memory payload = bytes("p");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.onboard.selector, abi.encode(b.memberId, payload)
        );
        IAdmin(address(diamond)).destroy();

        vm.expectRevert(ICore.ClusterDestroyed_.selector);
        ICore(address(diamond)).onboard(auth, b.memberId, payload);
    }

    function test_onboard_revertsOnRetired() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);
        bytes memory payload = bytes("p");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.onboard.selector, abi.encode(b.memberId, payload)
        );
        IAdmin(address(diamond)).retireMember(a.memberId);

        vm.expectRevert(ICore.MemberRetired_.selector);
        ICore(address(diamond)).onboard(auth, b.memberId, payload);
    }

    function test_onboard_canStackMultipleMessages() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        MemberKeys memory b = _mintMember(2);

        for (uint256 i = 0; i < 3; i++) {
            bytes memory payload = abi.encodePacked("msg-", i);
            ICore.CallAuth memory auth = _signCall(
                a.memberId, a.derivedPriv,
                ICore.onboard.selector, abi.encode(b.memberId, payload)
            );
            ICore(address(diamond)).onboard(auth, b.memberId, payload);
        }

        CoreStorage.OnboardMsg[] memory mailbox = ICore(address(diamond)).getOnboarding(b.memberId);
        assertEq(mailbox.length, 3, "3 messages stacked");
        assertEq(keccak256(mailbox[0].encryptedPayload), keccak256(abi.encodePacked("msg-", uint256(0))));
        assertEq(keccak256(mailbox[1].encryptedPayload), keccak256(abi.encodePacked("msg-", uint256(1))));
        assertEq(keccak256(mailbox[2].encryptedPayload), keccak256(abi.encodePacked("msg-", uint256(2))));
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TESTS — per-call auth (replay protection)
    // ═══════════════════════════════════════════════════════════════════════

    function test_callAuth_replayProtection() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        bytes memory newEp = bytes("ep-once");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.updateEndpoint.selector, abi.encode(newEp)
        );

        // First call succeeds.
        ICore(address(diamond)).updateEndpoint(auth, newEp);
        // Replay with identical auth -> BadNonce (nonce already incremented).
        vm.expectRevert(ICore.BadNonce.selector);
        ICore(address(diamond)).updateEndpoint(auth, newEp);
    }

    function test_callAuth_nonceIncrementOnSuccess() public withDiamond {
        MemberKeys memory a = _mintMember(1);
        assertEq(ICore(address(diamond)).memberNonce(a.memberId), 0, "nonce starts at 0");

        bytes memory newEp = bytes("ep");
        ICore.CallAuth memory auth = _signCall(
            a.memberId, a.derivedPriv,
            ICore.updateEndpoint.selector, abi.encode(newEp)
        );
        ICore(address(diamond)).updateEndpoint(auth, newEp);

        assertEq(ICore(address(diamond)).memberNonce(a.memberId), 1, "nonce incremented to 1");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TESTS — predictMember
    // ═══════════════════════════════════════════════════════════════════════

    function test_predictMember_matchesFactoryPredict() public withDiamond {
        bytes32 salt = bytes32(uint256(42));
        address predictedByCore = ICore(address(diamond)).predictMember(salt, DSTACK_ATTESTATION_ID);
        address predictedByFactory = factory.predict(address(diamond), salt, DSTACK_ATTESTATION_ID);
        assertEq(predictedByCore, predictedByFactory, "predict match");
    }

    function test_predictMember_changesPerSalt() public withDiamond {
        address a = ICore(address(diamond)).predictMember(bytes32(uint256(1)), DSTACK_ATTESTATION_ID);
        address b = ICore(address(diamond)).predictMember(bytes32(uint256(2)), DSTACK_ATTESTATION_ID);
        assertTrue(a != b, "different salts -> different addrs");
    }

    function test_predictMember_changesAcrossClusters() public withDiamond {
        bytes32 salt = bytes32(uint256(7));
        address aHere = ICore(address(diamond)).predictMember(salt, DSTACK_ATTESTATION_ID);
        // Factory's effective-salt is keccak(cluster, attestationId, salt),
        // so a different cluster address must yield a different prediction.
        address otherCluster = address(0xC1);
        address bElsewhere = factory.predict(otherCluster, salt, DSTACK_ATTESTATION_ID);
        assertTrue(aHere != bElsewhere, "different clusters -> different addrs");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TESTS — message helpers (replay-protection invariants)
    // ═══════════════════════════════════════════════════════════════════════

    function test_registrationMessage_includesChainId() public withDiamond {
        bytes memory ep = hex"aa";
        bytes memory pep = hex"bb";
        bytes32 h1 = ICore(address(diamond)).registrationMessage(address(0x1), ep, pep, "x");
        vm.chainId(99999);
        bytes32 h2 = ICore(address(diamond)).registrationMessage(address(0x1), ep, pep, "x");
        assertTrue(h1 != h2, "chainId binds");
    }

    function test_registrationMessage_includesClusterAddress() public withDiamond {
        bytes memory ep = hex"aa";
        bytes memory pep = hex"bb";
        bytes32 h1 = ICore(address(diamond)).registrationMessage(address(0x1), ep, pep, "x");
        // Recompute under a hypothetical OTHER cluster address. The
        // _REGISTER_MSG_PREFIX constant is private to CoreFacet; reconstruct
        // it inline. Drift fails the test loudly via h1 == h2.
        bytes32 h2 = keccak256(
            abi.encode(
                "teesql-cluster-register:v3",
                block.chainid,
                address(0xCAFE), // hypothetical other cluster
                "test-cluster",
                address(0x1),
                ep,
                pep,
                "x"
            )
        );
        assertTrue(h1 != h2, "cluster address binds");
    }

    function test_callMessage_includesSelector() public withDiamond {
        bytes memory args = hex"deadbeef";
        bytes32 h1 = ICore(address(diamond)).callMessage(
            keccak256("m"), 0, ICore.updateEndpoint.selector, args
        );
        bytes32 h2 = ICore(address(diamond)).callMessage(
            keccak256("m"), 0, ICore.updatePublicEndpoint.selector, args
        );
        assertTrue(h1 != h2, "selector binds");
    }

    function test_witnessMessage_includesEpoch() public withDiamond {
        bytes32 deposed = keccak256("d");
        bytes32 voucher = keccak256("v");
        bytes32 h1 = ICore(address(diamond)).witnessMessage(deposed, 1, voucher);
        bytes32 h2 = ICore(address(diamond)).witnessMessage(deposed, 2, voucher);
        assertTrue(h1 != h2, "epoch binds");
    }
}
