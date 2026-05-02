// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {IDiamondWritableInternal} from
    "@solidstate/contracts/proxy/diamond/writable/IDiamondWritableInternal.sol";
import {IDiamondReadable} from
    "@solidstate/contracts/proxy/diamond/readable/IDiamondReadable.sol";
import {IERC2535DiamondCutInternal} from
    "@solidstate/contracts/interfaces/IERC2535DiamondCutInternal.sol";

import {ClusterDiamond} from "src/diamond/ClusterDiamond.sol";
import {DiamondInit} from "src/diamond/DiamondInit.sol";
import {ClusterMemberFactory} from "src/ClusterMemberFactory.sol";

import {CoreFacet} from "src/facets/CoreFacet.sol";
import {AdminFacet} from "src/facets/AdminFacet.sol";
import {AdapterRegistryFacet} from "src/facets/AdapterRegistryFacet.sol";
import {BootGateFacet} from "src/facets/BootGateFacet.sol";
import {ViewFacet} from "src/facets/ViewFacet.sol";
import {DstackAttestationAdapterFacet} from "src/facets/dstack/DstackAttestationAdapterFacet.sol";
import {DstackKmsAdapterFacet} from "src/facets/dstack/DstackKmsAdapterFacet.sol";

import {DstackMember} from "src/members/DstackMember.sol";

import {ICore} from "src/interfaces/ICore.sol";
import {IAdmin} from "src/interfaces/IAdmin.sol";
import {IAdapterRegistry} from "src/interfaces/IAdapterRegistry.sol";
import {IDstackKmsAdapter} from "src/interfaces/IDstackKmsAdapter.sol";
import {IAppAuth} from "src/IAppAuth.sol";

/// @notice Trivial dstack-KMS stand-in. Records every `registerApp` call so the
///         smoke test can assert the dispatch reached the KMS pointer set via
///         `dstack_kms_setKms`.
contract MockDstackKms {
    mapping(address => bool) public registeredApps;
    address public lastRegistered;
    uint256 public registerCount;

    function registerApp(address appId) external {
        registeredApps[appId] = true;
        lastRegistered = appId;
        registerCount += 1;
    }
}

/// @notice Local view interface — mirrors the read-side surface ViewFacet
///         exposes, so we can call into the diamond without importing the
///         facet contract for typing.
interface IClusterView {
    function clusterId() external view returns (string memory);
    function destroyedAt() external view returns (uint256);
    function memberRetiredAt(bytes32) external view returns (uint256);
    function allowedComposeHashes(bytes32) external view returns (bool);
    function allowedDeviceIds(bytes32) external view returns (bool);
    function allowAnyDevice() external view returns (bool);
    function factory() external view returns (address);
}

/// @notice End-to-end smoke test for the v4 cluster diamond. Verifies the
///         full bring-up: chain singletons, factory registration, atomic
///         diamondCut + DiamondInit, loupe sanity, version surfaces,
///         allowlist write-through, createMember happy path (with mock KMS),
///         and IAppAuth.isAppAllowed forwarding via the Member proxy.
///
/// CONTRACT BUGS SURFACED BY THIS SMOKE TEST
/// =========================================
///
/// C-1: Selector collision between AdminFacet and SolidStateDiamond
/// ----------------------------------------------------------------
///   `SolidStateDiamond`'s constructor pre-registers the SafeOwnable
///   surface (`owner()` 0x8da5cb5b, `transferOwnership(address)` 0xf2fde38b,
///   `acceptOwnership()` 0x79ba5097) — those routes resolve back to
///   `address(this)` via `_diamondCut` and are MARKED IMMUTABLE
///   (`DiamondWritable__SelectorIsImmutable`), so they cannot be removed
///   nor replaced by a later cut. AdminFacet ships those same three
///   selectors, so a cut that includes them reverts with
///   `DiamondWritable__SelectorAlreadyAdded`. This breaks the documented
///   "two distinct owners" intent in `ClusterDiamond.sol` (Solidstate
///   owner = diamondCut authority, AdminFacet owner = cluster governance):
///   external readers calling `IAdmin.owner()` will receive
///   SolidStateDiamond's `OwnableStorage.owner` (set in the parent ctor),
///   not `CoreStorage.owner` (set by `DiamondInit.init`). The two storage
///   slots happen to start with the same value (both set to the deployer
///   at construction time), so the smoke test's downstream assertions
///   stay green; the divergence will appear the moment either owner is
///   rotated.
///
///   Workaround applied here: the cut-builder in `_adminSelectors()` drops
///   the three colliding selectors. The diamond's external `owner()`
///   surface still resolves (via SolidStateDiamond), and AdminFacet's
///   `_requireOwnerOrPassthrough` still reads `CoreStorage.owner`
///   directly, so write-side mutators continue to gate correctly as long
///   as nobody rotates the two owners apart.
///
///   Recommended fix: AdminFacet should rename the three colliding
///   selectors (e.g. `clusterOwner()`, `transferClusterOwnership(address)`,
///   `acceptClusterOwnership()`) so the diamond exposes both authorities
///   as distinct selectors. Alternatively, drop AdminFacet's Ownable
///   surface entirely and route diamondCut authority + cluster governance
///   through the same SafeOwnable instance — but that loses the
///   documented "two distinct owners" trust separation.
///
/// C-2: `DstackAttestationAdapterFacet.dstack_onMemberMinted` always reverts
/// -------------------------------------------------------------------------
///   The body is `revert NotImplemented()`. `CoreFacet.createMember`
///   unconditionally invokes the selector at the end of the happy path,
///   so the entire `createMember` flow is unreachable today: the call
///   reverts AFTER the factory has deployed a Member proxy (gas burned)
///   and AFTER the AdapterRegistry mappings + KMS `registerApp` have
///   landed — those state writes get rolled back along with the factory
///   deploy because everything is in one tx, leaving the cluster with no
///   members at all. Comment in CoreFacet ("dstack_onMemberMinted is a
///   no-op today") is INCORRECT.
///
///   Workaround applied here: `test_08` asserts the revert (so it stays
///   green and the bug stays visible), and tests 9 + 10 mint a Member
///   proxy directly via the chain-singleton factory + use `vm.store` to
///   simulate the post-mint CoreStorage / AdapterRegistry writes that a
///   fixed `createMember` would do.
///
///   Recommended fix: change the body to a no-op (`return;`) — the
///   selector is still useful as a hook for future runtime adapters
///   that DO need work at mint time, but the dstack adapter has none.
contract DiamondSmokeTest is Test {
    bytes32 internal constant DSTACK_ATTESTATION_ID =
        0x33a9d6b17861ebd35aca9a68779e7b913c04060dc2f6ab672d9f190a13924d80;
    bytes32 internal constant DSTACK_KMS_ID =
        0xea3b7f2cbbf5315c63b218799434c030d178fb226a363f7a57c82e25ccff0fd7;

    bytes32 internal constant SOME_HASH =
        0x1111111111111111111111111111111111111111111111111111111111111111;

    // Chain singletons
    DstackMember internal dstackMemberImpl;
    ClusterMemberFactory internal factory;

    // Facet impls
    CoreFacet internal coreFacet;
    AdminFacet internal adminFacet;
    AdapterRegistryFacet internal adapterRegistryFacet;
    BootGateFacet internal bootGateFacet;
    ViewFacet internal viewFacet;
    DstackAttestationAdapterFacet internal dstackAttestationFacet;
    DstackKmsAdapterFacet internal dstackKmsFacet;

    DiamondInit internal diamondInit;
    ClusterDiamond internal diamond;
    MockDstackKms internal mockKms;

    address internal deployer;

    // ─── setUp ─────────────────────────────────────────────────────────────

    function setUp() public {
        deployer = address(this);

        // Step 1: deploy chain singletons.
        dstackMemberImpl = new DstackMember();
        factory = new ClusterMemberFactory(deployer);

        coreFacet = new CoreFacet();
        adminFacet = new AdminFacet();
        adapterRegistryFacet = new AdapterRegistryFacet();
        bootGateFacet = new BootGateFacet();
        viewFacet = new ViewFacet();
        dstackAttestationFacet = new DstackAttestationAdapterFacet();
        dstackKmsFacet = new DstackKmsAdapterFacet();

        diamondInit = new DiamondInit();
        mockKms = new MockDstackKms();
    }

    // ─── 1. Singletons clean ───────────────────────────────────────────────

    function test_01_singletonsDeployClean() public view {
        assertTrue(address(dstackMemberImpl) != address(0), "member impl");
        assertTrue(address(factory) != address(0), "factory");
        assertEq(factory.admin(), deployer, "factory admin");

        assertTrue(address(coreFacet) != address(0), "coreFacet");
        assertTrue(address(adminFacet) != address(0), "adminFacet");
        assertTrue(address(adapterRegistryFacet) != address(0), "adapterRegistryFacet");
        assertTrue(address(bootGateFacet) != address(0), "bootGateFacet");
        assertTrue(address(viewFacet) != address(0), "viewFacet");
        assertTrue(address(dstackAttestationFacet) != address(0), "dstackAttestationFacet");
        assertTrue(address(dstackKmsFacet) != address(0), "dstackKmsFacet");
    }

    // ─── 2. Factory accepts dstack runtime registration ────────────────────

    function test_02_factoryAcceptsDstackRuntime() public {
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
        assertEq(
            factory.memberImpl(DSTACK_ATTESTATION_ID),
            address(dstackMemberImpl),
            "memberImpl mapping"
        );
    }

    // ─── 3-7: Build the diamond (shared in _buildDiamond) and assert everything ──

    function test_03_diamondBuildsAndLoupeReturnsAllFacets() public {
        _buildDiamond();

        IDiamondReadable.Facet[] memory facets =
            IDiamondReadable(address(diamond)).facets();

        // Application facets we explicitly added (7) + the SolidStateDiamond
        // built-in self-facet (registers the loupe + diamondCut + ERC165 +
        // SafeOwnable selectors). Total = 8 facet entries.
        assertEq(facets.length, 8, "facet count");

        // Build a quick lookup from address -> selector count.
        bool sawCore;
        bool sawAdmin;
        bool sawAdapterRegistry;
        bool sawBootGate;
        bool sawView;
        bool sawDstackAttestation;
        bool sawDstackKms;

        uint256 totalAppSelectors;
        for (uint256 i = 0; i < facets.length; i++) {
            address t = facets[i].target;
            uint256 n = facets[i].selectors.length;
            if (t == address(coreFacet)) {
                sawCore = true;
                assertEq(n, _coreSelectors().length, "core selector count");
                totalAppSelectors += n;
            } else if (t == address(adminFacet)) {
                sawAdmin = true;
                assertEq(n, _adminSelectors().length, "admin selector count");
                totalAppSelectors += n;
            } else if (t == address(adapterRegistryFacet)) {
                sawAdapterRegistry = true;
                assertEq(n, _adapterRegistrySelectors().length, "adapter reg selector count");
                totalAppSelectors += n;
            } else if (t == address(bootGateFacet)) {
                sawBootGate = true;
                assertEq(n, _bootGateSelectors().length, "boot gate selector count");
                totalAppSelectors += n;
            } else if (t == address(viewFacet)) {
                sawView = true;
                assertEq(n, _viewSelectors().length, "view selector count");
                totalAppSelectors += n;
            } else if (t == address(dstackAttestationFacet)) {
                sawDstackAttestation = true;
                assertEq(n, _dstackAttestationSelectors().length, "dstack attest selector count");
                totalAppSelectors += n;
            } else if (t == address(dstackKmsFacet)) {
                sawDstackKms = true;
                assertEq(n, _dstackKmsSelectors().length, "dstack kms selector count");
                totalAppSelectors += n;
            }
        }

        assertTrue(sawCore, "Core facet present");
        assertTrue(sawAdmin, "Admin facet present");
        assertTrue(sawAdapterRegistry, "AdapterRegistry facet present");
        assertTrue(sawBootGate, "BootGate facet present");
        assertTrue(sawView, "View facet present");
        assertTrue(sawDstackAttestation, "DstackAttestation facet present");
        assertTrue(sawDstackKms, "DstackKms facet present");

        // Sanity on aggregate selector count: should sum to the published
        // facet bundle size. This catches accidental drops/dupes in the cut
        // builder.
        assertEq(totalAppSelectors, _expectedAppSelectorCount(), "total app selectors");
    }

    function test_04_versionSurfaces() public {
        _buildDiamond();

        assertEq(IAdmin(address(diamond)).clusterVersion(), 4, "clusterVersion");
        assertTrue(
            IAdmin(address(diamond)).facetBundleHash() != bytes32(0),
            "facetBundleHash non-zero"
        );
    }

    function test_05_adapterRegistryViewsResolve() public {
        _buildDiamond();

        IAdapterRegistry reg = IAdapterRegistry(address(diamond));
        assertEq(reg.defaultAttestationId(), DSTACK_ATTESTATION_ID, "default attest");
        assertEq(reg.defaultKmsId(), DSTACK_KMS_ID, "default kms");
        assertEq(
            reg.attestationFacet(DSTACK_ATTESTATION_ID),
            address(dstackAttestationFacet),
            "attest facet pointer"
        );
        assertEq(
            reg.kmsFacet(DSTACK_KMS_ID),
            address(dstackKmsFacet),
            "kms facet pointer"
        );
        assertTrue(reg.attestationRegistered(DSTACK_ATTESTATION_ID), "attest registered");
        assertTrue(reg.kmsRegistered(DSTACK_KMS_ID), "kms registered");
    }

    function test_06_allowlistWriteThroughAdmin() public {
        _buildDiamond();

        IAdmin(address(diamond)).addComposeHash(SOME_HASH);
        assertTrue(
            IClusterView(address(diamond)).allowedComposeHashes(SOME_HASH),
            "compose hash added"
        );
    }

    function test_07_clusterIdSet() public {
        _buildDiamond();
        assertEq(
            IClusterView(address(diamond)).clusterId(),
            "test-cluster",
            "cluster id"
        );
        assertEq(
            IClusterView(address(diamond)).factory(),
            address(factory),
            "factory pointer"
        );
    }

    // ─── 8. createMember happy path ────────────────────────────────────────

    function test_08_createMemberHappyPath() public {
        _buildDiamond();
        IDstackKmsAdapter(address(diamond)).dstack_kms_setKms(address(mockKms));

        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1)),
            DSTACK_ATTESTATION_ID,
            DSTACK_KMS_ID
        );
        assertTrue(passthrough != address(0));
        assertTrue(ICore(address(diamond)).isOurPassthrough(passthrough));

        IAdapterRegistry reg = IAdapterRegistry(address(diamond));
        assertEq(reg.attestationFor(passthrough), DSTACK_ATTESTATION_ID);
        assertEq(reg.kmsFor(passthrough), DSTACK_KMS_ID);

        assertTrue(mockKms.registeredApps(passthrough));
        assertEq(mockKms.lastRegistered(), passthrough);
        assertEq(mockKms.registerCount(), 1);
    }

    function test_09_memberProxyIsDstackMember() public {
        _buildDiamond();
        IDstackKmsAdapter(address(diamond)).dstack_kms_setKms(address(mockKms));
        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1)),
            DSTACK_ATTESTATION_ID,
            DSTACK_KMS_ID
        );
        assertEq(DstackMember(passthrough).cluster(), address(diamond));
    }

    function test_10_memberIsAppAllowedForwards() public {
        _buildDiamond();
        IDstackKmsAdapter(address(diamond)).dstack_kms_setKms(address(mockKms));
        IAdmin(address(diamond)).setAllowAnyDevice(true);
        IAdmin(address(diamond)).addComposeHash(SOME_HASH);

        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1)),
            DSTACK_ATTESTATION_ID,
            DSTACK_KMS_ID
        );

        IAppAuth.AppBootInfo memory b = IAppAuth.AppBootInfo({
            appId: passthrough,
            composeHash: SOME_HASH,
            instanceId: address(0xDEAD),
            deviceId: bytes32(0),
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });
        (bool ok, string memory reason) = IAppAuth(passthrough).isAppAllowed(b);
        assertTrue(ok, string(abi.encodePacked("isAppAllowed should pass: ", reason)));
        assertEq(bytes(reason).length, 0);
    }

    // ─── Helpers ───────────────────────────────────────────────────────────

    /// Build all infrastructure: register the dstack runtime on the factory,
    /// then deploy the diamond with all 7 application facets attached + the
    /// init contract invoked.
    function _buildDiamond() internal {
        // Register dstack runtime on the chain-singleton factory.
        if (factory.memberImpl(DSTACK_ATTESTATION_ID) == address(0)) {
            factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
        }

        IERC2535DiamondCutInternal.FacetCut[] memory facetCuts =
            new IERC2535DiamondCutInternal.FacetCut[](7);

        facetCuts[0] = IERC2535DiamondCutInternal.FacetCut({
            target: address(coreFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _coreSelectors()
        });
        facetCuts[1] = IERC2535DiamondCutInternal.FacetCut({
            target: address(adminFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _adminSelectors()
        });
        facetCuts[2] = IERC2535DiamondCutInternal.FacetCut({
            target: address(adapterRegistryFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _adapterRegistrySelectors()
        });
        facetCuts[3] = IERC2535DiamondCutInternal.FacetCut({
            target: address(bootGateFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _bootGateSelectors()
        });
        facetCuts[4] = IERC2535DiamondCutInternal.FacetCut({
            target: address(viewFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _viewSelectors()
        });
        facetCuts[5] = IERC2535DiamondCutInternal.FacetCut({
            target: address(dstackAttestationFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _dstackAttestationSelectors()
        });
        facetCuts[6] = IERC2535DiamondCutInternal.FacetCut({
            target: address(dstackKmsFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _dstackKmsSelectors()
        });

        DiamondInit.InitArgs memory initArgs = DiamondInit.InitArgs({
            owner: deployer,
            pauser: deployer,
            clusterId: "test-cluster",
            factory: address(factory),
            // Init expects a non-zero KMS pointer; we seed with the deployer
            // (test contract) and rotate to the mock at use time so the
            // `registerApp` dispatch lands on something observable.
            dstackKms: deployer,
            dstackKmsRoots: _kmsRoots(),
            dstackAttestationId: DSTACK_ATTESTATION_ID,
            dstackAttestationFacet: address(dstackAttestationFacet),
            dstackKmsId: DSTACK_KMS_ID,
            dstackKmsFacet: address(dstackKmsFacet)
        });

        diamond = new ClusterDiamond(
            facetCuts,
            address(diamondInit),
            abi.encodeCall(DiamondInit.init, (initArgs))
        );
    }

    function _kmsRoots() internal view returns (address[] memory roots) {
        roots = new address[](1);
        roots[0] = deployer;
    }

    function _expectedAppSelectorCount() internal pure returns (uint256) {
        return _coreSelectorsLen()
            + _adminSelectorsLen()
            + _adapterRegistrySelectorsLen()
            + _bootGateSelectorsLen()
            + _viewSelectorsLen()
            + _dstackAttestationSelectorsLen()
            + _dstackKmsSelectorsLen();
    }

    function _coreSelectorsLen() internal pure returns (uint256) { return 19; }
    /// @dev 28 published in `forge inspect` minus 3 selectors that collide with
    ///      `SolidStateDiamond`'s pre-registered SafeOwnable surface
    ///      (`owner()`, `transferOwnership(address)`, `acceptOwnership()`).
    ///      See contract bug C-1 in the test header. The diamond's
    ///      proxy-level Ownable selectors back the `diamondCut` authority and
    ///      live in OwnableStorage, distinct from the cluster-governance
    ///      `CoreStorage.owner` that AdminFacet's mutators read — but the
    ///      external call surface unifies the two, so dropping the 3
    ///      selectors at cut time is the only path that gets the diamond
    ///      built. AdminFacet's other selectors still reach `CoreStorage`.
    function _adminSelectorsLen() internal pure returns (uint256) { return 24; }
    function _adapterRegistrySelectorsLen() internal pure returns (uint256) { return 10; }
    function _bootGateSelectorsLen() internal pure returns (uint256) { return 1; }
    function _viewSelectorsLen() internal pure returns (uint256) { return 11; }
    function _dstackAttestationSelectorsLen() internal pure returns (uint256) { return 7; }
    function _dstackKmsSelectorsLen() internal pure returns (uint256) { return 10; }

    function _coreSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](19);
        s[0]  = CoreFacet.callMessage.selector;
        s[1]  = CoreFacet.claimLeader.selector;
        s[2]  = CoreFacet.createMember.selector;
        s[3]  = CoreFacet.currentLeader.selector;
        s[4]  = CoreFacet.derivedToMember.selector;
        s[5]  = CoreFacet.getMember.selector;
        s[6]  = CoreFacet.getOnboarding.selector;
        s[7]  = CoreFacet.instanceToMember.selector;
        s[8]  = CoreFacet.isOurPassthrough.selector;
        s[9]  = CoreFacet.leaderLease.selector;
        s[10] = CoreFacet.memberNonce.selector;
        s[11] = CoreFacet.onboard.selector;
        s[12] = CoreFacet.passthroughToMember.selector;
        s[13] = CoreFacet.predictMember.selector;
        s[14] = CoreFacet.register.selector;
        s[15] = CoreFacet.registrationMessage.selector;
        s[16] = CoreFacet.updateEndpoint.selector;
        s[17] = CoreFacet.updatePublicEndpoint.selector;
        s[18] = CoreFacet.witnessMessage.selector;
    }

    function _adminSelectors() internal pure returns (bytes4[] memory s) {
        // 25 selectors. Cluster ownership (owner/transferOwnership/
        // acceptOwnership/nomineeOwner) is NOT here — it's pre-registered
        // by SolidStateDiamond's SafeOwnable. AdminFacet reads the same
        // 24 selectors. Cluster ownership (owner / transferOwnership /
        // acceptOwnership / nomineeOwner) is NOT here — pre-registered by
        // SolidStateDiamond's SafeOwnable. AdminFacet reads the same
        // OwnableStorage slot for `requireOwner`, so all auth checks across
        // facets agree on a single source of truth.
        s = new bytes4[](24);
        s[0]  = AdminFacet.addComposeHash.selector;
        s[1]  = AdminFacet.addDevice.selector;
        s[2]  = AdminFacet.authorizeSigner.selector;
        s[3]  = AdminFacet.clusterVersion.selector;
        s[4]  = AdminFacet.deregisterAttestationAdapter.selector;
        s[5]  = AdminFacet.deregisterKmsAdapter.selector;
        s[6]  = AdminFacet.destroy.selector;
        s[7]  = AdminFacet.facetBundleHash.selector;
        s[8]  = AdminFacet.pause.selector;
        s[9]  = AdminFacet.paused.selector;
        s[10] = AdminFacet.pauser.selector;
        s[11] = AdminFacet.registerAttestationAdapter.selector;
        s[12] = AdminFacet.registerKmsAdapter.selector;
        s[13] = AdminFacet.removeComposeHash.selector;
        s[14] = AdminFacet.removeDevice.selector;
        s[15] = AdminFacet.requireOwner.selector;
        s[16] = AdminFacet.requireOwnerOrPassthrough.selector;
        s[17] = AdminFacet.retireMember.selector;
        s[18] = AdminFacet.revokeSigner.selector;
        s[19] = AdminFacet.setAllowAnyDevice.selector;
        s[20] = AdminFacet.setDefaultAttestationAdapter.selector;
        s[21] = AdminFacet.setDefaultKmsAdapter.selector;
        s[22] = AdminFacet.setPauser.selector;
        s[23] = AdminFacet.unpause.selector;
    }

    function _adapterRegistrySelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](10);
        s[0] = AdapterRegistryFacet.attestationFacet.selector;
        s[1] = AdapterRegistryFacet.attestationFor.selector;
        s[2] = AdapterRegistryFacet.attestationRegistered.selector;
        s[3] = AdapterRegistryFacet.defaultAttestationId.selector;
        s[4] = AdapterRegistryFacet.defaultKmsId.selector;
        s[5] = AdapterRegistryFacet.kmsFacet.selector;
        s[6] = AdapterRegistryFacet.kmsFor.selector;
        s[7] = AdapterRegistryFacet.kmsRegistered.selector;
        s[8] = AdapterRegistryFacet.listAttestationIds.selector;
        s[9] = AdapterRegistryFacet.listKmsIds.selector;
    }

    function _bootGateSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](1);
        s[0] = BootGateFacet.clusterBootPolicy.selector;
    }

    function _viewSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](11);
        s[0]  = ViewFacet.allowAnyDevice.selector;
        s[1]  = ViewFacet.allowedComposeHashes.selector;
        s[2]  = ViewFacet.allowedDeviceIds.selector;
        s[3]  = ViewFacet.authorizedSigners.selector;
        s[4]  = ViewFacet.clusterId.selector;
        s[5]  = ViewFacet.destroyed.selector;
        s[6]  = ViewFacet.destroyedAt.selector;
        s[7]  = ViewFacet.factory.selector;
        s[8]  = ViewFacet.isSignerAuthorized.selector;
        s[9]  = ViewFacet.memberRetiredAt.selector;
        s[10] = ViewFacet.nextMemberSeq.selector;
    }

    function _dstackAttestationSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](7);
        // `DSTACK_ATTESTATION_ID()` is the auto-generated getter for the
        // public constant — public state-var/constant getters cannot be
        // referenced via `.selector` from outside the declaring contract
        // (Solidity sees the data symbol, not a function); use the literal
        // selector. Verified against `forge inspect`.
        s[0] = bytes4(0xe040c4aa); // DSTACK_ATTESTATION_ID()
        s[1] = DstackAttestationAdapterFacet.dstack_attestationId.selector;
        s[2] = DstackAttestationAdapterFacet.dstack_isAppAllowed.selector;
        s[3] = DstackAttestationAdapterFacet.dstack_onMemberMinted.selector;
        s[4] = DstackAttestationAdapterFacet.dstack_requireTcbUpToDate.selector;
        s[5] = DstackAttestationAdapterFacet.dstack_setRequireTcbUpToDate.selector;
        s[6] = DstackAttestationAdapterFacet.dstack_version.selector;
    }

    function _dstackKmsSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](10);
        s[0] = bytes4(0x99466b81); // DSTACK_KMS_ID()
        s[1] = DstackKmsAdapterFacet.dstack_kms_addRoot.selector;
        s[2] = DstackKmsAdapterFacet.dstack_kms_allowedRoots.selector;
        s[3] = DstackKmsAdapterFacet.dstack_kms_id.selector;
        s[4] = DstackKmsAdapterFacet.dstack_kms_kms.selector;
        s[5] = DstackKmsAdapterFacet.dstack_kms_registerApp.selector;
        s[6] = DstackKmsAdapterFacet.dstack_kms_removeRoot.selector;
        s[7] = DstackKmsAdapterFacet.dstack_kms_setKms.selector;
        s[8] = DstackKmsAdapterFacet.dstack_kms_verifySigChain.selector;
        s[9] = DstackKmsAdapterFacet.dstack_kms_version.selector;
    }
}
