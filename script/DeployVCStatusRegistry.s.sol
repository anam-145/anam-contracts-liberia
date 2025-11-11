// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/VCStatusRegistry.sol";

contract DeployVCStatusRegistry is Script {
    function run() external returns (VCStatusRegistry) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        VCStatusRegistry registry = new VCStatusRegistry();

        vm.stopBroadcast();

        console.log("VCStatusRegistry deployed at:", address(registry));
        console.log("Deployer has ISSUER_ROLE:", registry.hasRole(registry.ISSUER_ROLE(), msg.sender));
        console.log("Owner:", registry.owner());

        return registry;
    }
}
