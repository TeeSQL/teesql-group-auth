// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {TeeGroupAuth} from "../src/TeeGroupAuth.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Deploy is Script {
    function run() external {
        // Configure these for your deployment
        address owner = msg.sender;

        // Example KMS roots — replace with real addresses
        address[] memory trustedKmsRoots = new address[](1);
        trustedKmsRoots[0] = vm.envAddress("KMS_ROOT");

        // Example allowed code IDs — replace with real values
        bytes32[] memory allowedCodes = new bytes32[](1);
        allowedCodes[0] = vm.envBytes32("ALLOWED_CODE_ID");

        vm.startBroadcast();

        // Deploy implementation
        TeeGroupAuth implementation = new TeeGroupAuth();
        console.log("Implementation:", address(implementation));

        // Encode initialize call
        bytes memory initData = abi.encodeCall(
            TeeGroupAuth.initialize,
            (owner, trustedKmsRoots, allowedCodes)
        );

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        console.log("Proxy:", address(proxy));

        // Verify initialization
        TeeGroupAuth tga = TeeGroupAuth(address(proxy));
        console.log("Owner:", tga.owner());
        console.log("Secret version:", tga.secretVersion());
        console.log("KMS root trusted:", tga.trustedKmsRoots(trustedKmsRoots[0]));

        vm.stopBroadcast();
    }
}
