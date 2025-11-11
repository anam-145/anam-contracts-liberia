// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/DIDRegistry.sol";

contract DeployDIDRegistry is Script {
    function run() external returns (DIDRegistry) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        DIDRegistry registry = new DIDRegistry();

        vm.stopBroadcast();

        console.log("DIDRegistry deployed at:", address(registry));
        console.log("Deployer has ISSUER_ROLE:", registry.hasRole(registry.ISSUER_ROLE(), msg.sender));
        console.log("Owner:", registry.owner());

        return registry;
    }
}
