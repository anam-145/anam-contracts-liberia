// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/EventFactory.sol";

contract EventFactoryTest is Test {
    EventFactory public factory;
    address public usdcAddress;
    address public deployer;

    function setUp() public {
        deployer = address(this);
        usdcAddress = address(0x1234);
        factory = new EventFactory(usdcAddress);
    }

    function test_DeploySuccessfully() public view {
        assertTrue(address(factory) != address(0));
    }

    function test_SetUSDCAddressInConstructor() public view {
        assertEq(factory.usdcAddress(), usdcAddress);
    }

    function test_GrantDefaultAdminRoleToDeployer() public view {
        assertTrue(factory.hasRole(factory.DEFAULT_ADMIN_ROLE(), deployer));
    }

    function test_RevertWhenCreatingEventWithZeroUSDCAddress() public {
        vm.expectRevert("Invalid USDC address");
        new EventFactory(address(0));
    }

    function test_RevertWhenCreatingEventWithInvalidTimeRange() public {
        uint256 startTime = block.timestamp + 1 days;
        uint256 endTime = block.timestamp; // endTime <= startTime
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectRevert("Invalid time range");
        factory.createEvent(
            startTime,
            endTime,
            amountPerDay,
            maxParticipants,
            maxTotalPayments,
            approvers,
            verifiers
        );
    }

    function test_RevertWhenCreatingEventWithZeroAmountPerDay() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 0; // Zero amount
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectRevert("Invalid amount per day");
        factory.createEvent(
            startTime,
            endTime,
            amountPerDay,
            maxParticipants,
            maxTotalPayments,
            approvers,
            verifiers
        );
    }

    function test_RevertWhenCreatingEventWithZeroMaxParticipants() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 0; // Zero max participants
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectRevert("Invalid max participants");
        factory.createEvent(
            startTime,
            endTime,
            amountPerDay,
            maxParticipants,
            maxTotalPayments,
            approvers,
            verifiers
        );
    }

    function test_RevertWhenCreatingEventWithZeroMaxTotalPayments() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 0; // Zero max total payments
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectRevert("Invalid max total payments");
        factory.createEvent(
            startTime,
            endTime,
            amountPerDay,
            maxParticipants,
            maxTotalPayments,
            approvers,
            verifiers
        );
    }
}
