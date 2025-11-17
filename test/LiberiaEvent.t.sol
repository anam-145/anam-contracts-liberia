// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LiberiaEvent} from "../src/LiberiaEvent.sol";

contract LiberiaEventTest is Test {
    LiberiaEvent public eventContract;
    address public usdcAddress;
    address public systemAdmin;

    event ParticipantRegistered(address indexed participant, address indexed admin);
    event ParticipantRemoved(address indexed participant, address indexed admin);

    function setUp() public {
        usdcAddress = address(0x1234);
        systemAdmin = address(this);

        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        uint256 maxTotalPayments = 3;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        eventContract = new LiberiaEvent(
            usdcAddress,
            startTime,
            endTime,
            amountPerDay,
            maxParticipants,
            maxTotalPayments,
            approvers,
            verifiers,
            systemAdmin
        );
    }

    function test_InitializeEventContractWithCorrectUSDCAddress() public view {
        assertEq(eventContract.usdcAddress(), usdcAddress);
    }

    function test_InitializeEventContractWithCorrectTimeRange() public view {
        uint256 expectedStartTime = block.timestamp;
        uint256 expectedEndTime = block.timestamp + 7 days;

        assertEq(eventContract.startTime(), expectedStartTime);
        assertEq(eventContract.endTime(), expectedEndTime);
    }

    function test_InitializeEventContractWithCorrectAmountPerDay() public view {
        uint256 expectedAmountPerDay = 100 ether;

        assertEq(eventContract.amountPerDay(), expectedAmountPerDay);
    }

    function test_InitializeEventContractWithCorrectMaxParticipants() public view {
        uint256 expectedMaxParticipants = 50;

        assertEq(eventContract.maxParticipants(), expectedMaxParticipants);
    }

    function test_InitializeEventContractWithCorrectMaxTotalPayments() public view {
        uint256 expectedMaxTotalPayments = 3;

        assertEq(eventContract.maxTotalPayments(), expectedMaxTotalPayments);
    }

    function test_GrantApproverRoleToApproversList() public view {
        bytes32 approverRole = eventContract.APPROVER_ROLE();

        assertTrue(eventContract.hasRole(approverRole, address(0x1111)));
    }

    function test_GrantVerifierRoleToVerifiersList() public view {
        bytes32 verifierRole = eventContract.VERIFIER_ROLE();

        assertTrue(eventContract.hasRole(verifierRole, address(0x2222)));
    }

    function test_SetSystemAdminAsOwner() public view {
        bytes32 systemAdminRole = eventContract.SYSTEM_ADMIN_ROLE();

        assertTrue(eventContract.hasRole(systemAdminRole, systemAdmin));
    }

    function test_AllowSystemAdminToRegisterAParticipant() public {
        address participant = address(0x9999);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant);

        assertTrue(eventContract.isParticipant(participant));
    }

    function test_EmitParticipantRegisteredEventWhenParticipantIsRegistered() public {
        address participant = address(0x9999);

        vm.expectEmit(true, true, false, false, address(eventContract));
        emit ParticipantRegistered(participant, systemAdmin);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant);
    }

    function test_RevertWhenNonSystemAdminTriesToRegisterParticipant() public {
        address participant = address(0x9999);
        address nonAdmin = address(0x8888);

        vm.prank(nonAdmin);
        vm.expectRevert();
        eventContract.registerParticipant(participant);
    }

    function test_RevertWhenRegisteringZeroAddressAsParticipant() public {
        vm.prank(systemAdmin);
        vm.expectRevert("Invalid participant address");
        eventContract.registerParticipant(address(0));
    }

    function test_RevertWhenParticipantCountExceedsMaxParticipants() public {
        // maxParticipants is set to 50 in setUp
        // Register 50 participants
        vm.startPrank(systemAdmin);
        for (uint256 i = 1; i <= 50; i++) {
            eventContract.registerParticipant(address(uint160(i)));
        }

        // Try to register the 51st participant, should revert
        vm.expectRevert("Max participants reached");
        eventContract.registerParticipant(address(uint160(51)));
        vm.stopPrank();
    }

    function test_AllowRegisteringMultipleParticipantsAtOnce() public {
        address[] memory participants = new address[](3);
        participants[0] = address(0x1001);
        participants[1] = address(0x1002);
        participants[2] = address(0x1003);

        vm.prank(systemAdmin);
        eventContract.registerParticipants(participants);

        assertTrue(eventContract.isParticipant(participants[0]));
        assertTrue(eventContract.isParticipant(participants[1]));
        assertTrue(eventContract.isParticipant(participants[2]));
        assertEq(eventContract.participantCount(), 3);
    }

    function test_AllowSystemAdminToRemoveAParticipant() public {
        address participant = address(0x9999);

        vm.startPrank(systemAdmin);
        eventContract.registerParticipant(participant);
        assertTrue(eventContract.isParticipant(participant));
        assertEq(eventContract.participantCount(), 1);

        eventContract.removeParticipant(participant);
        assertFalse(eventContract.isParticipant(participant));
        assertEq(eventContract.participantCount(), 0);
        vm.stopPrank();
    }

    function test_EmitParticipantRemovedEventWhenParticipantIsRemoved() public {
        address participant = address(0x9999);

        vm.startPrank(systemAdmin);
        eventContract.registerParticipant(participant);

        vm.expectEmit(true, true, false, false, address(eventContract));
        emit ParticipantRemoved(participant, systemAdmin);

        eventContract.removeParticipant(participant);
        vm.stopPrank();
    }

    function test_RevertWhenRemovingNonExistentParticipant() public {
        address participant = address(0x9999);

        vm.prank(systemAdmin);
        vm.expectRevert("Participant not registered");
        eventContract.removeParticipant(participant);
    }

    function test_TrackTotalParticipantCountCorrectly() public {
        vm.startPrank(systemAdmin);

        // Initially count should be 0
        assertEq(eventContract.participantCount(), 0);

        // Register 3 participants
        eventContract.registerParticipant(address(0x1001));
        assertEq(eventContract.participantCount(), 1);

        eventContract.registerParticipant(address(0x1002));
        assertEq(eventContract.participantCount(), 2);

        eventContract.registerParticipant(address(0x1003));
        assertEq(eventContract.participantCount(), 3);

        // Remove 1 participant
        eventContract.removeParticipant(address(0x1002));
        assertEq(eventContract.participantCount(), 2);

        // Register another participant
        eventContract.registerParticipant(address(0x1004));
        assertEq(eventContract.participantCount(), 3);

        // Remove 2 participants
        eventContract.removeParticipant(address(0x1001));
        assertEq(eventContract.participantCount(), 2);

        eventContract.removeParticipant(address(0x1003));
        assertEq(eventContract.participantCount(), 1);

        vm.stopPrank();
    }
}
