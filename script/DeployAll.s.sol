// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/DIDRegistry.sol";
import "../src/VCStatusRegistry.sol";

contract DeployAll is Script {
    function run() external returns (DIDRegistry didRegistry, VCStatusRegistry vcRegistry) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        didRegistry = new DIDRegistry();
        console.log("DIDRegistry deployed at:", address(didRegistry));

        vcRegistry = new VCStatusRegistry();
        console.log("VCStatusRegistry deployed at:", address(vcRegistry));

        vm.stopBroadcast();

        console.log("\n=== Deployment Summary ===");
        console.log("DIDRegistry:", address(didRegistry));
        console.log("VCStatusRegistry:", address(vcRegistry));
        console.log("Deployer has DEFAULT_ADMIN_ROLE and ISSUER_ROLE on both contracts");

        return (didRegistry, vcRegistry);
    }
}
