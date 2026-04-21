// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {DstackVerifier} from "../src/DstackVerifier.sol";
import {TEEBridge} from "../src/TEEBridge.sol";

/// @notice Deploys TEEBridge + DstackVerifier behind ERC1967 proxies.
///
/// Required env vars:
///   OWNER              — address to own both proxies (Safe or EOA)
///   KMS_ROOT           — first trusted KMS root signer address to seed
///                        DstackVerifier with (e.g. Phala Base KMS root)
///
/// Optional env vars:
///   ALLOWED_CODE_ID    — first compose hash to seed TEEBridge with.
///                        If unset or 0x0, TEEBridge is initialized with
///                        an empty allowedCode set; admin adds codes
///                        post-deploy via Safe TX.
///
/// Both proxies can have more roots / codes / verifiers added post-deploy
/// via the admin functions; only the initial seed is set here.
contract Deploy is Script {
    function run() external {
        address owner = vm.envAddress("OWNER");
        address kmsRoot = vm.envAddress("KMS_ROOT");
        bytes32 allowedCodeId = vm.envOr("ALLOWED_CODE_ID", bytes32(0));

        vm.startBroadcast();

        // --- DstackVerifier ---
        DstackVerifier verifierImpl = new DstackVerifier();
        console.log("DstackVerifier implementation:", address(verifierImpl));

        address[] memory kmsRoots = new address[](1);
        kmsRoots[0] = kmsRoot;

        bytes memory verifierInit = abi.encodeCall(DstackVerifier.initialize, (owner, kmsRoots));
        ERC1967Proxy verifierProxy = new ERC1967Proxy(address(verifierImpl), verifierInit);
        console.log("DstackVerifier proxy:        ", address(verifierProxy));

        // --- TEEBridge ---
        TEEBridge bridgeImpl = new TEEBridge();
        console.log("TEEBridge implementation:    ", address(bridgeImpl));

        address[] memory verifiers = new address[](1);
        verifiers[0] = address(verifierProxy);

        bytes32[] memory allowedCodes;
        if (allowedCodeId != bytes32(0)) {
            allowedCodes = new bytes32[](1);
            allowedCodes[0] = allowedCodeId;
        } else {
            allowedCodes = new bytes32[](0);
        }

        bytes memory bridgeInit = abi.encodeCall(TEEBridge.initialize, (owner, verifiers, allowedCodes));
        ERC1967Proxy bridgeProxy = new ERC1967Proxy(address(bridgeImpl), bridgeInit);
        console.log("TEEBridge proxy:             ", address(bridgeProxy));

        vm.stopBroadcast();

        console.log("---");
        console.log("Owner:                       ", owner);
        console.log("Seed KMS root:               ", kmsRoot);
        if (allowedCodeId != bytes32(0)) {
            console.log("Seed allowed code:");
            console.logBytes32(allowedCodeId);
        } else {
            console.log("Seed allowed code:           (none; add via Safe TX post-deploy)");
        }
    }
}
