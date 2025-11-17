// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {EventFactory} from "../src/EventFactory.sol";
import {LiberiaEvent} from "../src/LiberiaEvent.sol";

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
        assertTrue(factory.hasRole(factory.SYSTEM_ADMIN_ROLE(), deployer));
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
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers);
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
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers);
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
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers);
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
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers);
    }

    function test_CreateNewEventContractWithValidParameters() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address eventAddress = factory.createEvent(
            startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers
        );

        assertTrue(eventAddress != address(0));
    }

    function test_EmitEventCreatedEventWhenEventIsCreated() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectEmit(false, true, false, false);
        emit EventCreated(address(0), deployer);

        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers);
    }

    event EventCreated(address indexed eventAddress, address indexed creator);

    function test_StoreCreatedEventAddressInEventsArray() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address eventAddress = factory.createEvent(
            startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers
        );

        assertEq(factory.getEventsLength(), 1);
        assertEq(factory.events(0), eventAddress);
    }

    function test_AssignApproversToTheCreatedEventContract() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](2);
        approvers[0] = address(0x1111);
        approvers[1] = address(0x2222);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x3333);

        address eventAddress = factory.createEvent(
            startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers
        );

        LiberiaEvent eventContract = LiberiaEvent(eventAddress);
        bytes32 approverRole = eventContract.APPROVER_ROLE();

        assertTrue(eventContract.hasRole(approverRole, approvers[0]));
        assertTrue(eventContract.hasRole(approverRole, approvers[1]));
    }

    function test_AssignVerifiersToTheCreatedEventContract() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](2);
        verifiers[0] = address(0x2222);
        verifiers[1] = address(0x3333);

        address eventAddress = factory.createEvent(
            startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers
        );

        LiberiaEvent eventContract = LiberiaEvent(eventAddress);
        bytes32 verifierRole = eventContract.VERIFIER_ROLE();

        assertTrue(eventContract.hasRole(verifierRole, verifiers[0]));
        assertTrue(eventContract.hasRole(verifierRole, verifiers[1]));
    }

    function test_OnlyAllowSystemAdminToCreateEvents() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        // Grant SYSTEM_ADMIN role to a new address
        address systemAdmin = address(0x9999);
        bytes32 systemAdminRole = factory.SYSTEM_ADMIN_ROLE();

        vm.prank(deployer);
        factory.grantRole(systemAdminRole, systemAdmin);

        // Verify the system admin can create events
        vm.prank(systemAdmin);
        address eventAddress = factory.createEvent(
            startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers
        );

        assertTrue(eventAddress != address(0));
    }

    function test_RevertWhenNonAdminTriesToCreateEvent() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        // Try to create event as non-admin
        address nonAdmin = address(0x8888);

        vm.prank(nonAdmin);
        vm.expectRevert();
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers);
    }

    function test_CreateMultipleEventsIndependently() public {
        address[] memory approvers1 = new address[](1);
        approvers1[0] = address(0x1111);
        address[] memory verifiers1 = new address[](1);
        verifiers1[0] = address(0x2222);

        address eventAddress1 =
            factory.createEvent(block.timestamp, block.timestamp + 7 days, 100 ether, 50, 3, approvers1, verifiers1);

        address[] memory approvers2 = new address[](1);
        approvers2[0] = address(0x3333);
        address[] memory verifiers2 = new address[](1);
        verifiers2[0] = address(0x4444);

        address eventAddress2 = factory.createEvent(
            block.timestamp + 1 days, block.timestamp + 14 days, 200 ether, 100, 5, approvers2, verifiers2
        );

        // Verify both events exist and are different
        assertTrue(eventAddress1 != address(0));
        assertTrue(eventAddress2 != address(0));
        assertTrue(eventAddress1 != eventAddress2);

        // Verify events are stored in the array
        assertEq(factory.getEventsLength(), 2);
        assertEq(factory.events(0), eventAddress1);
        assertEq(factory.events(1), eventAddress2);

        // Verify each event has independent roles
        LiberiaEvent event1 = LiberiaEvent(eventAddress1);
        LiberiaEvent event2 = LiberiaEvent(eventAddress2);

        bytes32 approverRole = event1.APPROVER_ROLE();
        bytes32 verifierRole = event1.VERIFIER_ROLE();

        // Event 1 has its own approvers and verifiers
        assertTrue(event1.hasRole(approverRole, address(0x1111)));
        assertFalse(event1.hasRole(approverRole, address(0x3333)));
        assertTrue(event1.hasRole(verifierRole, address(0x2222)));
        assertFalse(event1.hasRole(verifierRole, address(0x4444)));

        // Event 2 has its own approvers and verifiers
        assertTrue(event2.hasRole(approverRole, address(0x3333)));
        assertFalse(event2.hasRole(approverRole, address(0x1111)));
        assertTrue(event2.hasRole(verifierRole, address(0x4444)));
        assertFalse(event2.hasRole(verifierRole, address(0x2222)));
    }

    function test_ReturnCorrectEventAddressAfterCreation() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address returnedAddress = factory.createEvent(
            startTime, endTime, amountPerDay, maxParticipants, maxTotalPayments, approvers, verifiers
        );

        // Verify the returned address is a valid LiberiaEvent contract
        assertTrue(returnedAddress != address(0));

        // Verify it's actually a LiberiaEvent by checking it has the expected interface
        LiberiaEvent eventContract = LiberiaEvent(returnedAddress);
        bytes32 approverRole = eventContract.APPROVER_ROLE();
        bytes32 verifierRole = eventContract.VERIFIER_ROLE();

        // Verify the contract has the correct roles defined
        assertTrue(approverRole != bytes32(0));
        assertTrue(verifierRole != bytes32(0));

        // Verify the returned address matches what's stored in the events array
        assertEq(factory.events(0), returnedAddress);
    }
}
