// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/DIDRegistry.sol";

contract DeployDIDRegistry is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        DIDRegistry registry = new DIDRegistry();

        vm.stopBroadcast();

        console.log("===========================================");
        console.log("DIDRegistry deployed to:", address(registry));
        console.log("Deployer (owner):", msg.sender);
        console.log("Chain ID:", block.chainid);
        console.log("===========================================");
    }
}
