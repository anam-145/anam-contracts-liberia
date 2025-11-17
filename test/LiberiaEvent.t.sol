// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LiberiaEvent} from "../src/LiberiaEvent.sol";

contract LiberiaEventTest is Test {
    LiberiaEvent public eventContract;
    address public usdcAddress;
    address public systemAdmin;

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
        bytes32 defaultAdminRole = eventContract.DEFAULT_ADMIN_ROLE();

        assertTrue(eventContract.hasRole(defaultAdminRole, systemAdmin));
    }
}
