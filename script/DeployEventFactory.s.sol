// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/EventFactory.sol";

contract DeployEventFactory is Script {
    function run() external returns (EventFactory) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address usdcAddress = vm.envAddress("USDC_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);

        EventFactory factory = new EventFactory(usdcAddress);

        vm.stopBroadcast();

        console.log("EventFactory deployed at:", address(factory));
        console.log("USDC Address:", factory.usdcAddress());
        console.log("Deployer has SYSTEM_ADMIN_ROLE:", factory.hasRole(factory.SYSTEM_ADMIN_ROLE(), msg.sender));

        return factory;
    }
}
