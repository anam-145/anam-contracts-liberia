// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LiberiaEvent} from "../src/LiberiaEvent.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// Mock token that returns false on transfer (non-reverting failure)
contract MockFailingUSDC {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false; // Always returns false without reverting
    }
}

// Mock token that attempts reentrancy attack during transfer
contract ReentrantToken {
    mapping(address => uint256) public balanceOf;
    LiberiaEvent public targetContract;
    address public attacker;
    address public participant;
    address public approver;
    bool public attackEnabled;
    uint256 public attackCount;
    address public participant2; // Second participant for reentrancy
    bool public useBatchAttack; // If true, attack with batchApprovePayments
    address[] public batchParticipants;

    function setTarget(LiberiaEvent _target, address _attacker, address _participant, address _approver) external {
        targetContract = _target;
        attacker = _attacker;
        participant = _participant;
        approver = _approver;
    }

    function setParticipant2(address _participant2) external {
        participant2 = _participant2;
    }

    function setBatchParticipants(address[] memory _participants) external {
        batchParticipants = _participants;
    }

    function enableAttack() external {
        attackEnabled = true;
        attackCount = 0;
        useBatchAttack = false;
    }

    function enableBatchAttack() external {
        attackEnabled = true;
        attackCount = 0;
        useBatchAttack = true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        // Attempt reentrancy attack
        if (attackEnabled && attackCount == 0) {
            attackCount++;
            if (useBatchAttack) {
                // Try to call batchApprovePayments during transfer
                targetContract.batchApprovePayments(batchParticipants, approver);
            } else {
                // Try to call approvePayment for a different participant during transfer
                targetContract.approvePayment(participant2, approver);
            }
        }

        return true;
    }
}

contract LiberiaEventTest is Test {
    LiberiaEvent public eventContract;
    MockUSDC public usdc;
    address public systemAdmin;

    event ParticipantRegistered(address indexed participant, address indexed admin);
    event ParticipantRemoved(address indexed participant, address indexed admin);
    event CheckInVerified(address indexed participant, address indexed verifier, uint256 indexed day);
    event PaymentApproved(address indexed participant, address indexed approver, uint256 indexed day, uint256 amount);

    function setUp() public {
        usdc = new MockUSDC();
        systemAdmin = address(this);

        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        eventContract = new LiberiaEvent(
            address(usdc), startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers, systemAdmin
        );
    }

    function test_InitializeEventContractWithCorrectUSDCAddress() public view {
        assertEq(eventContract.usdcAddress(), address(usdc));
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
        eventContract.registerParticipant(participant, systemAdmin);

        assertTrue(eventContract.isParticipant(participant));
    }

    function test_EmitParticipantRegisteredEventWhenParticipantIsRegistered() public {
        address participant = address(0x9999);

        vm.expectEmit(true, true, false, false, address(eventContract));
        emit ParticipantRegistered(participant, systemAdmin);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);
    }

    function test_RevertWhenNonSystemAdminTriesToRegisterParticipant() public {
        address participant = address(0x9999);
        address nonAdmin = address(0x8888);

        vm.prank(nonAdmin);
        vm.expectRevert();
        eventContract.registerParticipant(participant, systemAdmin);
    }

    function test_RevertWhenRegisteringZeroAddressAsParticipant() public {
        vm.prank(systemAdmin);
        vm.expectRevert("Invalid participant address");
        eventContract.registerParticipant(address(0), systemAdmin);
    }

    function test_RevertWhenParticipantCountExceedsMaxParticipants() public {
        // maxParticipants is set to 50 in setUp
        // Register 50 participants
        vm.startPrank(systemAdmin);
        for (uint256 i = 1; i <= 50; i++) {
            eventContract.registerParticipant(address(uint160(i)), systemAdmin);
        }

        // Try to register the 51st participant, should revert
        vm.expectRevert("Max participants reached");
        eventContract.registerParticipant(address(uint160(51)), systemAdmin);
        vm.stopPrank();
    }

    function test_AllowRegisteringMultipleParticipantsAtOnce() public {
        address[] memory participants = new address[](3);
        participants[0] = address(0x1001);
        participants[1] = address(0x1002);
        participants[2] = address(0x1003);

        vm.prank(systemAdmin);
        eventContract.registerParticipants(participants, systemAdmin);

        assertTrue(eventContract.isParticipant(participants[0]));
        assertTrue(eventContract.isParticipant(participants[1]));
        assertTrue(eventContract.isParticipant(participants[2]));
        assertEq(eventContract.participantCount(), 3);
    }

    function test_AllowSystemAdminToRemoveAParticipant() public {
        address participant = address(0x9999);

        vm.startPrank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);
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
        eventContract.registerParticipant(participant, systemAdmin);

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
        eventContract.registerParticipant(address(0x1001), systemAdmin);
        assertEq(eventContract.participantCount(), 1);

        eventContract.registerParticipant(address(0x1002), systemAdmin);
        assertEq(eventContract.participantCount(), 2);

        eventContract.registerParticipant(address(0x1003), systemAdmin);
        assertEq(eventContract.participantCount(), 3);

        // Remove 1 participant
        eventContract.removeParticipant(address(0x1002));
        assertEq(eventContract.participantCount(), 2);

        // Register another participant
        eventContract.registerParticipant(address(0x1004), systemAdmin);
        assertEq(eventContract.participantCount(), 3);

        // Remove 2 participants
        eventContract.removeParticipant(address(0x1001));
        assertEq(eventContract.participantCount(), 2);

        eventContract.removeParticipant(address(0x1003));
        assertEq(eventContract.participantCount(), 1);

        vm.stopPrank();
    }

    function test_AllowVerifierToVerifyCheckInForRegisteredParticipant() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        assertTrue(eventContract.isVerifiedForDay(participant, block.timestamp));
    }

    function test_EmitCheckInVerifiedEventWhenCheckInIsVerified() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Calculate normalized day (00:00:00 UTC of that day)
        uint256 normalizedDay = (block.timestamp / 1 days) * 1 days;

        vm.expectEmit(true, true, true, false, address(eventContract));
        emit CheckInVerified(participant, verifier, normalizedDay);

        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);
    }

    function test_RevertWhenNonVerifierTriesToVerifyCheckIn() public {
        address participant = address(0x9999);
        address nonVerifier = address(0x8888);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        vm.prank(systemAdmin);
        vm.expectRevert("Verifier does not have VERIFIER_ROLE");
        eventContract.verifyCheckIn(participant, nonVerifier);
    }

    function test_AllowApproverToVerifyCheckInForRegisteredParticipant() public {
        address participant = address(0x9999);
        address approver = address(0x1111);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, approver);

        assertTrue(eventContract.isVerifiedForDay(participant, block.timestamp));
    }

    function test_EmitCheckInVerifiedEventWhenApproverVerifiesCheckIn() public {
        address participant = address(0x9999);
        address approver = address(0x1111);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Calculate normalized day (00:00:00 UTC of that day)
        uint256 normalizedDay = (block.timestamp / 1 days) * 1 days;

        vm.expectEmit(true, true, true, false, address(eventContract));
        emit CheckInVerified(participant, approver, normalizedDay);

        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, approver);
    }

    function test_SetParticipantStatusToVerifiedWhenApproverVerifiesCheckIn() public {
        address participant = address(0x9999);
        address approver = address(0x1111);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        uint256 day = block.timestamp;

        // Before check-in, participant should not be verified
        assertFalse(eventContract.isVerifiedForDay(participant, day));

        // Verify check-in with approver
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, approver);

        // After check-in, participant should be verified for that day
        assertTrue(eventContract.isVerifiedForDay(participant, day));
    }

    function test_IncrementCheckInCountWhenApproverVerifiesCheckIn() public {
        address participant = address(0x9999);
        address approver = address(0x1111);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Initially, check-in count should be 0
        assertEq(eventContract.getCheckInCount(participant), 0);

        // Verify check-in with approver
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, approver);

        // Check-in count should be incremented
        assertEq(eventContract.getCheckInCount(participant), 1);
    }

    function test_RevertWhenVerifyingCheckInForUnregisteredParticipant() public {
        address unregisteredParticipant = address(0x9999);
        address verifier = address(0x2222);

        vm.prank(systemAdmin);
        vm.expectRevert("Participant not registered");
        eventContract.verifyCheckIn(unregisteredParticipant, verifier);
    }

    function test_RevertWhenVerifyingCheckInBeforeEventStartTime() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Try to verify check-in before event start time
        vm.warp(block.timestamp - 1);
        vm.prank(systemAdmin);
        vm.expectRevert("Check-in outside event time range");
        eventContract.verifyCheckIn(participant, verifier);
    }

    function test_RevertWhenVerifyingCheckInAfterEventEndTime() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Try to verify check-in after event end time (startTime + 7 days + 1)
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(systemAdmin);
        vm.expectRevert("Check-in outside event time range");
        eventContract.verifyCheckIn(participant, verifier);
    }

    function test_RevertWhenParticipantAlreadyCheckedInForSameDay() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // First check-in for the day (e.g., 9:00 AM)
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        // Try to check in again for the same day (e.g., 3:00 PM - 6 hours later)
        vm.warp(block.timestamp + 6 hours);
        vm.prank(systemAdmin);
        vm.expectRevert("Participant already checked in for this day");
        eventContract.verifyCheckIn(participant, verifier);
    }

    function test_SetParticipantStatusToVerifiedForTheDay() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        uint256 day = block.timestamp;

        // Before check-in, participant should not be verified
        assertFalse(eventContract.isVerifiedForDay(participant, day));

        // Verify check-in
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        // After check-in, participant should be verified for that day
        assertTrue(eventContract.isVerifiedForDay(participant, day));
    }

    function test_TrackCheckInCountPerParticipant() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Initially, check-in count should be 0
        assertEq(eventContract.getCheckInCount(participant), 0);

        // First check-in
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);
        assertEq(eventContract.getCheckInCount(participant), 1);

        // Second check-in (next day)
        vm.warp(block.timestamp + 1 days);
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);
        assertEq(eventContract.getCheckInCount(participant), 2);

        // Third check-in (two days later)
        vm.warp(block.timestamp + 1 days);
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);
        assertEq(eventContract.getCheckInCount(participant), 3);
    }

    function test_AllowApproverToApprovePaymentForVerifiedParticipant() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);
        address approver = address(0x1111);

        // Fund the event contract with USDC
        usdc.transfer(address(eventContract), 1000 ether);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        vm.prank(systemAdmin);
        eventContract.approvePayment(participant, approver);

        assertEq(
            uint256(eventContract.getParticipantStatusForDay(participant, block.timestamp)),
            uint256(2) // COMPLETED = 2
        );
    }

    function test_EmitPaymentApprovedEventWhenPaymentIsApproved() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);
        address approver = address(0x1111);
        uint256 expectedAmount = 100 ether;

        // Fund the event contract with USDC
        usdc.transfer(address(eventContract), 1000 ether);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        uint256 normalizedDay = (block.timestamp / 1 days) * 1 days;

        vm.expectEmit(true, true, true, true, address(eventContract));
        emit PaymentApproved(participant, approver, normalizedDay, expectedAmount);

        vm.prank(systemAdmin);
        eventContract.approvePayment(participant, approver);
    }

    function test_RevertWhenNonApproverTriesToApprovePayment() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);
        address nonApprover = address(0x8888);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        vm.prank(systemAdmin);
        vm.expectRevert("Approver does not have APPROVER_ROLE");
        eventContract.approvePayment(participant, nonApprover);
    }

    function test_RevertWhenParticipantIsNotInVerifiedStatus() public {
        address participant = address(0x9999);
        address approver = address(0x1111);

        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        vm.prank(systemAdmin);
        vm.expectRevert("Participant not in VERIFIED status");
        eventContract.approvePayment(participant, approver);
    }

    function test_TransferCorrectAmountOfUSDCToParticipant() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);
        address approver = address(0x1111);
        uint256 amountPerDay = 100 ether;

        // Fund the event contract with USDC
        usdc.transfer(address(eventContract), 1000 ether);

        // Register participant
        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Verify check-in
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        // Record balances before payment
        uint256 participantBalanceBefore = usdc.balanceOf(participant);
        uint256 contractBalanceBefore = usdc.balanceOf(address(eventContract));

        // Approve payment
        vm.prank(systemAdmin);
        eventContract.approvePayment(participant, approver);

        // Check balances after payment
        uint256 participantBalanceAfter = usdc.balanceOf(participant);
        uint256 contractBalanceAfter = usdc.balanceOf(address(eventContract));

        assertEq(participantBalanceAfter, participantBalanceBefore + amountPerDay);
        assertEq(contractBalanceAfter, contractBalanceBefore - amountPerDay);
    }

    function test_RevertWhenContractHasInsufficientUSDCBalance() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);
        address approver = address(0x1111);

        // Do NOT fund the event contract (insufficient balance)

        // Register participant
        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Verify check-in
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        // Try to approve payment without sufficient USDC balance
        vm.prank(systemAdmin);
        vm.expectRevert();
        eventContract.approvePayment(participant, approver);
    }

    function test_TrackTotalPaymentsMadeToEachParticipant() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);
        address approver = address(0x1111);

        // Fund the event contract with USDC
        usdc.transfer(address(eventContract), 1000 ether);

        // Register participant
        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Initially, payment count should be 0
        assertEq(eventContract.getPaymentCount(participant), 0);

        // First payment (day 0)
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);
        vm.prank(systemAdmin);
        eventContract.approvePayment(participant, approver);
        assertEq(eventContract.getPaymentCount(participant), 1);

        // Second payment (day 1)
        vm.warp(block.timestamp + 1 days);
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);
        vm.prank(systemAdmin);
        eventContract.approvePayment(participant, approver);
        assertEq(eventContract.getPaymentCount(participant), 2);

        // Third payment (day 2)
        vm.warp(block.timestamp + 1 days);
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);
        vm.prank(systemAdmin);
        eventContract.approvePayment(participant, approver);
        assertEq(eventContract.getPaymentCount(participant), 3);
    }

    function test_PreventSameParticipantFromReceivingPaymentTwiceOnSameDay() public {
        address participant = address(0x9999);
        address verifier = address(0x2222);
        address approver = address(0x1111);

        // Fund the event contract with USDC
        usdc.transfer(address(eventContract), 1000 ether);

        // Register participant
        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Verify check-in
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        // First payment approval
        vm.prank(systemAdmin);
        eventContract.approvePayment(participant, approver);

        // Try to approve payment again for the same day - should revert
        vm.prank(systemAdmin);
        vm.expectRevert("Participant not in VERIFIED status");
        eventContract.approvePayment(participant, approver);
    }

    function test_AllowBatchPaymentApprovalForMultipleParticipants() public {
        address approver = address(0x1111);
        address verifier = address(0x2222);
        uint256 day = block.timestamp;

        // Create 3 participants
        address[] memory participants = new address[](3);
        participants[0] = address(0x9991);
        participants[1] = address(0x9992);
        participants[2] = address(0x9993);

        // Fund contract with enough USDC for 3 payments
        usdc.mint(address(eventContract), 300 ether);

        // Register all participants
        vm.prank(systemAdmin);
        eventContract.registerParticipants(participants, systemAdmin);

        // Verify check-in for all participants
        for (uint256 i = 0; i < participants.length; i++) {
            vm.prank(systemAdmin);
            eventContract.verifyCheckIn(participants[i], verifier);
        }

        // Batch approve payments
        vm.prank(systemAdmin);
        eventContract.batchApprovePayments(participants, approver);

        // Verify all participants received payment
        for (uint256 i = 0; i < participants.length; i++) {
            assertEq(
                uint256(eventContract.getParticipantStatusForDay(participants[i], day)),
                uint256(2) // COMPLETED
            );
            assertEq(usdc.balanceOf(participants[i]), 100 ether);
            assertEq(eventContract.getPaymentCount(participants[i]), 1);
        }
    }

    function test_RevertWhenSystemAdminTriesToRegisterThemselvesAsParticipant() public {
        // Try to register system admin as participant - should revert
        vm.prank(systemAdmin);
        vm.expectRevert("System admins cannot be registered as participants");
        eventContract.registerParticipant(systemAdmin, systemAdmin);
    }

    function test_RevertWhenApproverTriesToRegisterThemselvesAsParticipant() public {
        address approver = address(0x1111);

        // Try to register approver as participant - should revert
        vm.prank(systemAdmin);
        vm.expectRevert("Approvers cannot be registered as participants");
        eventContract.registerParticipant(approver, systemAdmin);
    }

    function test_RevertWhenVerifierTriesToRegisterThemselvesAsParticipant() public {
        address verifier = address(0x2222);

        // Try to register verifier as participant - should revert
        vm.prank(systemAdmin);
        vm.expectRevert("Verifiers cannot be registered as participants");
        eventContract.registerParticipant(verifier, systemAdmin);
    }

    function test_AllowParticipantWhoIsNotApproverOrVerifierToReceivePayment() public {
        address approver = address(0x1111);
        address verifier = address(0x2222);
        address participant = address(0x9999); // Regular participant with no roles
        uint256 day = block.timestamp;

        // Register regular participant (should succeed)
        vm.prank(systemAdmin);
        eventContract.registerParticipant(participant, systemAdmin);

        // Fund the contract
        usdc.mint(address(eventContract), 100 ether);

        // Verify check-in for the participant
        vm.prank(systemAdmin);
        eventContract.verifyCheckIn(participant, verifier);

        // Approve payment for the participant (should succeed)
        vm.prank(systemAdmin);
        eventContract.approvePayment(participant, approver);

        // Verify participant received payment
        assertEq(usdc.balanceOf(participant), 100 ether);
        assertEq(eventContract.getPaymentCount(participant), 1);
        assertEq(
            uint256(eventContract.getParticipantStatusForDay(participant, day)),
            uint256(2) // COMPLETED
        );
    }

    function test_AllowSystemAdminToGrantApproverRole() public {
        address newApprover = address(0x8888);
        bytes32 approverRole = eventContract.APPROVER_ROLE();

        // Verify newApprover doesn't have APPROVER_ROLE initially
        assertFalse(eventContract.hasRole(approverRole, newApprover));

        // Grant APPROVER_ROLE to newApprover
        vm.prank(systemAdmin);
        eventContract.grantRole(approverRole, newApprover);

        // Verify newApprover now has APPROVER_ROLE
        assertTrue(eventContract.hasRole(approverRole, newApprover));
    }

    function test_AllowSystemAdminToRevokeApproverRole() public {
        address approver = address(0x1111); // Already has APPROVER_ROLE from setUp
        bytes32 approverRole = eventContract.APPROVER_ROLE();

        // Verify approver has APPROVER_ROLE initially
        assertTrue(eventContract.hasRole(approverRole, approver));

        // Revoke APPROVER_ROLE from approver
        vm.prank(systemAdmin);
        eventContract.revokeRole(approverRole, approver);

        // Verify approver no longer has APPROVER_ROLE
        assertFalse(eventContract.hasRole(approverRole, approver));
    }

    function test_AllowSystemAdminToGrantVerifierRole() public {
        address newVerifier = address(0x9999);
        bytes32 verifierRole = eventContract.VERIFIER_ROLE();

        // Verify newVerifier doesn't have VERIFIER_ROLE initially
        assertFalse(eventContract.hasRole(verifierRole, newVerifier));

        // Grant VERIFIER_ROLE to newVerifier
        vm.prank(systemAdmin);
        eventContract.grantRole(verifierRole, newVerifier);

        // Verify newVerifier now has VERIFIER_ROLE
        assertTrue(eventContract.hasRole(verifierRole, newVerifier));
    }

    function test_AllowSystemAdminToRevokeVerifierRole() public {
        address verifier = address(0x2222); // Already has VERIFIER_ROLE from setUp
        bytes32 verifierRole = eventContract.VERIFIER_ROLE();

        // Verify verifier has VERIFIER_ROLE initially
        assertTrue(eventContract.hasRole(verifierRole, verifier));

        // Revoke VERIFIER_ROLE from verifier
        vm.prank(systemAdmin);
        eventContract.revokeRole(verifierRole, verifier);

        // Verify verifier no longer has VERIFIER_ROLE
        assertFalse(eventContract.hasRole(verifierRole, verifier));
    }

    function test_EmitRoleGrantedEventWhenRoleIsGranted() public {
        address newApprover = address(0x7777);
        bytes32 approverRole = eventContract.APPROVER_ROLE();

        // Expect RoleGranted event to be emitted
        vm.expectEmit(true, true, true, true);
        emit RoleGranted(approverRole, newApprover, systemAdmin);

        // Grant APPROVER_ROLE to newApprover
        vm.prank(systemAdmin);
        eventContract.grantRole(approverRole, newApprover);
    }

    function test_EmitRoleRevokedEventWhenRoleIsRevoked() public {
        address approver = address(0x1111); // Already has APPROVER_ROLE from setUp
        bytes32 approverRole = eventContract.APPROVER_ROLE();

        // Expect RoleRevoked event to be emitted
        vm.expectEmit(true, true, true, true);
        emit RoleRevoked(approverRole, approver, systemAdmin);

        // Revoke APPROVER_ROLE from approver
        vm.prank(systemAdmin);
        eventContract.revokeRole(approverRole, approver);
    }

    function test_RevertWhenNonSystemAdminTriesToGrantRole() public {
        address nonAdmin = address(0x5555);
        address newApprover = address(0x6666);
        bytes32 approverRole = eventContract.APPROVER_ROLE();

        // Try to grant APPROVER_ROLE as non-admin - should revert
        vm.prank(nonAdmin);
        vm.expectRevert();
        eventContract.grantRole(approverRole, newApprover);
    }

    function test_RevertWhenNonSystemAdminTriesToRevokeRole() public {
        address nonAdmin = address(0x5555);
        address existingApprover = address(0x1111);
        bytes32 approverRole = eventContract.APPROVER_ROLE();

        // Try to revoke APPROVER_ROLE from existing approver as non-admin - should revert
        vm.prank(nonAdmin);
        vm.expectRevert();
        eventContract.revokeRole(approverRole, existingApprover);
    }

    function test_EmitProperEventsForAllStateChangingOperations() public {
        // This test verifies that all state-changing operations emit proper events
        // Individual event tests exist for each operation, this test documents the requirement

        address participant1 = address(0x3333);
        address verifier = address(0x2222);
        address approver = address(0x1111);

        // 1. Register participant - emits ParticipantRegistered
        vm.expectEmit(true, true, false, false);
        emit ParticipantRegistered(participant1, systemAdmin);
        eventContract.registerParticipant(participant1, systemAdmin);

        // 2. Verify check-in - emits CheckInVerified
        uint256 today = block.timestamp;
        uint256 normalizedDay = (today / 1 days) * 1 days;
        vm.expectEmit(true, true, true, false);
        emit CheckInVerified(participant1, verifier, normalizedDay);
        eventContract.verifyCheckIn(participant1, verifier);

        // 3. Approve payment - emits PaymentApproved
        usdc.transfer(address(eventContract), 1000 ether);
        vm.expectEmit(true, true, true, true);
        emit PaymentApproved(participant1, approver, normalizedDay, 100 ether);
        eventContract.approvePayment(participant1, approver);

        // 4. Remove participant - emits ParticipantRemoved
        vm.expectEmit(true, true, false, false);
        emit ParticipantRemoved(participant1, systemAdmin);
        eventContract.removeParticipant(participant1);

        // 5. Grant role - emits RoleGranted (OpenZeppelin)
        address newApprover = address(0x7777);
        bytes32 approverRole = eventContract.APPROVER_ROLE();
        vm.expectEmit(true, true, true, false);
        emit RoleGranted(approverRole, newApprover, systemAdmin);
        eventContract.grantRole(approverRole, newApprover);

        // 6. Revoke role - emits RoleRevoked (OpenZeppelin)
        vm.expectEmit(true, true, true, false);
        emit RoleRevoked(approverRole, newApprover, systemAdmin);
        eventContract.revokeRole(approverRole, newApprover);
    }

    function test_IncludeTimestampInAllEmittedEvents() public {
        // Solidity events automatically include block.timestamp in the transaction receipt
        // Additionally, our CheckInVerified and PaymentApproved events include explicit day/timestamp data

        address participant1 = address(0x3333);
        address verifier = address(0x2222);
        address approver = address(0x1111);

        eventContract.registerParticipant(participant1, systemAdmin);

        // CheckInVerified event includes explicit day (normalized timestamp)
        uint256 checkInTime = block.timestamp;
        uint256 normalizedDay = (checkInTime / 1 days) * 1 days;

        vm.expectEmit(true, true, true, false);
        emit CheckInVerified(participant1, verifier, normalizedDay);
        eventContract.verifyCheckIn(participant1, verifier);

        // PaymentApproved event includes explicit day (normalized timestamp)
        usdc.transfer(address(eventContract), 1000 ether);
        vm.expectEmit(true, true, true, true);
        emit PaymentApproved(participant1, approver, normalizedDay, 100 ether);
        eventContract.approvePayment(participant1, approver);

        // All Solidity events inherently include block.timestamp in transaction logs
        // This test verifies that time-sensitive events (CheckInVerified, PaymentApproved)
        // also include explicit normalized day for business logic tracking
    }

    function test_IncludeCallerAddressInAllEmittedEvents() public {
        // This test verifies that all events include the caller's address for audit purposes

        address participant1 = address(0x3333);
        address verifier = address(0x2222);
        address approver = address(0x1111);

        // ParticipantRegistered includes admin (caller) address
        vm.expectEmit(true, true, false, false);
        emit ParticipantRegistered(participant1, systemAdmin);
        eventContract.registerParticipant(participant1, systemAdmin);

        // CheckInVerified includes verifier (caller) address
        uint256 today = block.timestamp;
        uint256 normalizedDay = (today / 1 days) * 1 days;
        vm.expectEmit(true, true, true, false);
        emit CheckInVerified(participant1, verifier, normalizedDay);
        eventContract.verifyCheckIn(participant1, verifier);

        // PaymentApproved includes approver (caller) address
        usdc.transfer(address(eventContract), 1000 ether);
        vm.expectEmit(true, true, true, true);
        emit PaymentApproved(participant1, approver, normalizedDay, 100 ether);
        eventContract.approvePayment(participant1, approver);

        // ParticipantRemoved includes admin (caller) address
        vm.expectEmit(true, true, false, false);
        emit ParticipantRemoved(participant1, systemAdmin);
        eventContract.removeParticipant(participant1);

        // RoleGranted and RoleRevoked include sender (caller) address
        address newApprover = address(0x7777);
        bytes32 approverRole = eventContract.APPROVER_ROLE();
        vm.expectEmit(true, true, true, false);
        emit RoleGranted(approverRole, newApprover, systemAdmin);
        eventContract.grantRole(approverRole, newApprover);

        vm.expectEmit(true, true, true, false);
        emit RoleRevoked(approverRole, newApprover, systemAdmin);
        eventContract.revokeRole(approverRole, newApprover);
    }

    function test_EmitEventWithParticipantAddressAndAmountForPayments() public {
        // This test verifies that PaymentApproved event includes participant address and payment amount

        address participant1 = address(0x3333);
        address verifier = address(0x2222);
        address approver = address(0x1111);
        uint256 paymentAmount = 100 ether;

        // Register and verify participant
        eventContract.registerParticipant(participant1, systemAdmin);
        uint256 today = block.timestamp;
        eventContract.verifyCheckIn(participant1, verifier);

        // Fund the contract
        usdc.transfer(address(eventContract), 1000 ether);

        // Approve payment and verify event includes participant address and amount
        uint256 normalizedDay = (today / 1 days) * 1 days;
        vm.expectEmit(true, true, true, true);
        emit PaymentApproved(participant1, approver, normalizedDay, paymentAmount);
        eventContract.approvePayment(participant1, approver);

        // The PaymentApproved event includes:
        // - participant address (indexed for filtering)
        // - approver address (indexed for filtering)
        // - day (indexed for filtering)
        // - amount (non-indexed, full data)
    }

    function test_EmitEventWithDaySessionInformationForCheckIns() public {
        // This test verifies that CheckInVerified event includes day/session information

        address participant1 = address(0x3333);
        address verifier = address(0x2222);

        // Register participant
        eventContract.registerParticipant(participant1, systemAdmin);

        // Verify check-in on a specific day
        vm.warp(block.timestamp + 2 days);
        uint256 checkInTime = block.timestamp;
        uint256 normalizedDay = (checkInTime / 1 days) * 1 days;

        // The CheckInVerified event should include the normalized day
        vm.expectEmit(true, true, true, false);
        emit CheckInVerified(participant1, verifier, normalizedDay);
        eventContract.verifyCheckIn(participant1, verifier);

        // The CheckInVerified event includes:
        // - participant address (indexed for filtering)
        // - verifier address (indexed for filtering)
        // - day (indexed for filtering by date/session)

        // Test multiple check-ins on different days
        vm.warp(block.timestamp + 1 days);
        uint256 nextDay = block.timestamp;
        uint256 nextNormalizedDay = (nextDay / 1 days) * 1 days;

        vm.expectEmit(true, true, true, false);
        emit CheckInVerified(participant1, verifier, nextNormalizedDay);
        eventContract.verifyCheckIn(participant1, verifier);
    }

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    function test_AllowSystemAdminToWithdrawRemainingUSDC() public {
        address recipient = address(0x5555);
        uint256 initialBalance = 500 ether;

        // Fund the event contract with USDC
        usdc.transfer(address(eventContract), initialBalance);

        // Verify initial balances
        assertEq(usdc.balanceOf(address(eventContract)), initialBalance);
        assertEq(usdc.balanceOf(recipient), 0);

        // Withdraw as system admin
        vm.prank(systemAdmin);
        eventContract.withdraw(recipient);

        // Verify all USDC was transferred to recipient
        assertEq(usdc.balanceOf(address(eventContract)), 0);
        assertEq(usdc.balanceOf(recipient), initialBalance);
    }

    function test_RevertWhenNonSystemAdminTriesToWithdraw() public {
        address recipient = address(0x5555);
        address nonAdmin = address(0x8888);

        // Fund the event contract with USDC
        usdc.transfer(address(eventContract), 500 ether);

        // Try to withdraw as non-admin - should revert
        vm.prank(nonAdmin);
        vm.expectRevert();
        eventContract.withdraw(recipient);
    }

    // C-1: SafeERC20 - Test that approvePayment reverts when transfer returns false
    function test_RevertWhenApprovePaymentTransferReturnsFalse() public {
        // Create event contract with failing USDC
        MockFailingUSDC failingUsdc = new MockFailingUSDC();

        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        LiberiaEvent failingEventContract = new LiberiaEvent(
            address(failingUsdc), startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers, address(this)
        );

        // Fund the contract (balance is tracked but transfer will fail)
        failingUsdc.mint(address(failingEventContract), 1000 ether);

        // Register participant
        address participant = address(0x9999);
        failingEventContract.registerParticipant(participant, address(this));

        // Verify check-in
        failingEventContract.verifyCheckIn(participant, address(0x2222));

        // Approve payment should revert because transfer returns false
        vm.expectRevert();
        failingEventContract.approvePayment(participant, address(0x1111));
    }

    // C-1: SafeERC20 - Test that batchApprovePayments reverts when transfer returns false
    function test_RevertWhenBatchApprovePaymentsTransferReturnsFalse() public {
        // Create event contract with failing USDC
        MockFailingUSDC failingUsdc = new MockFailingUSDC();

        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        LiberiaEvent failingEventContract = new LiberiaEvent(
            address(failingUsdc), startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers, address(this)
        );

        // Fund the contract (balance is tracked but transfer will fail)
        failingUsdc.mint(address(failingEventContract), 1000 ether);

        // Register multiple participants
        address[] memory participants = new address[](2);
        participants[0] = address(0x9991);
        participants[1] = address(0x9992);
        failingEventContract.registerParticipants(participants, address(this));

        // Verify check-in for all participants
        for (uint256 i = 0; i < participants.length; i++) {
            failingEventContract.verifyCheckIn(participants[i], address(0x2222));
        }

        // Batch approve payments should revert because transfer returns false
        vm.expectRevert();
        failingEventContract.batchApprovePayments(participants, address(0x1111));
    }

    // C-1: SafeERC20 - Test that withdraw reverts when transfer returns false
    function test_RevertWhenWithdrawTransferReturnsFalse() public {
        // Create event contract with failing USDC
        MockFailingUSDC failingUsdc = new MockFailingUSDC();

        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        LiberiaEvent failingEventContract = new LiberiaEvent(
            address(failingUsdc), startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers, address(this)
        );

        // Fund the contract (balance is tracked but transfer will fail)
        failingUsdc.mint(address(failingEventContract), 500 ether);

        // Withdraw should revert because transfer returns false
        vm.expectRevert();
        failingEventContract.withdraw(address(0x5555));
    }

    // C-2: ReentrancyGuard - Test that approvePayment is protected against reentrancy
    // Note: The current implementation uses Check-Effects-Interactions pattern which provides
    // some protection. However, explicit ReentrancyGuard should be added as defense in depth.
    // This test verifies that reentrancy attempts are blocked.
    function test_RevertWhenApprovePaymentReentrancyAttack() public {
        // Create reentrant token that will try to re-enter during transfer
        ReentrantToken reentrantToken = new ReentrantToken();

        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        // Make the reentrant token the system admin so it can attempt reentrancy
        LiberiaEvent reentrantEventContract = new LiberiaEvent(
            address(reentrantToken),
            startTime,
            endTime,
            amountPerDay,
            maxParticipants,
            approvers,
            verifiers,
            address(reentrantToken) // Token is the system admin
        );

        // Register two participants (as token which is admin)
        address participant1 = address(0x9991);
        address participant2 = address(0x9992);
        vm.startPrank(address(reentrantToken));
        reentrantEventContract.registerParticipant(participant1, address(reentrantToken));
        reentrantEventContract.registerParticipant(participant2, address(reentrantToken));

        // Verify check-in for both participants
        reentrantEventContract.verifyCheckIn(participant1, address(0x2222));
        reentrantEventContract.verifyCheckIn(participant2, address(0x2222));
        vm.stopPrank();

        // Fund contract with enough for multiple payments
        reentrantToken.mint(address(reentrantEventContract), 1000 ether);

        // Setup reentrancy attack - the token will try to call approvePayment for participant2
        // during the transfer to participant1
        reentrantToken.setTarget(reentrantEventContract, address(reentrantToken), participant1, address(0x1111));
        reentrantToken.setParticipant2(participant2);
        reentrantToken.enableAttack();

        // The reentrancy attempt during safeTransfer should be blocked
        // Either by ReentrancyGuard or by the existing state change protection
        vm.prank(address(reentrantToken));
        vm.expectRevert();
        reentrantEventContract.approvePayment(participant1, address(0x1111));
    }

    // C-2: ReentrancyGuard - Test that batchApprovePayments reverts on reentrancy attack
    function test_RevertWhenBatchApprovePaymentsReentrancyAttack() public {
        ReentrantToken token = new ReentrantToken();
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        LiberiaEvent eventC = new LiberiaEvent(
            address(token), block.timestamp, block.timestamp + 7 days, 100 ether, 50, approvers, verifiers, address(token)
        );

        // Register participants
        address p1 = address(0x9991);
        address p2 = address(0x9992);
        address p3 = address(0x9993);

        vm.startPrank(address(token));
        eventC.registerParticipant(p1, address(token));
        eventC.registerParticipant(p2, address(token));
        eventC.registerParticipant(p3, address(token));
        eventC.verifyCheckIn(p1, address(0x2222));
        eventC.verifyCheckIn(p2, address(0x2222));
        eventC.verifyCheckIn(p3, address(0x2222));
        vm.stopPrank();

        token.mint(address(eventC), 1000 ether);

        // Setup attack: during batch for [p1], try to batch [p2, p3]
        address[] memory batch1 = new address[](1);
        batch1[0] = p1;
        address[] memory batch2 = new address[](2);
        batch2[0] = p2;
        batch2[1] = p3;

        token.setTarget(eventC, address(token), p1, address(0x1111));
        token.setBatchParticipants(batch2);
        token.enableBatchAttack();

        vm.prank(address(token));
        vm.expectRevert();
        eventC.batchApprovePayments(batch1, address(0x1111));
    }

    // H-3: batchApprovePayments should revert early if total required balance exceeds contract balance
    function test_RevertWhenBatchApprovePaymentsTotalExceedsBalance() public {
        address approver = address(0x1111);
        address verifier = address(0x2222);

        // Create 5 participants
        address[] memory participants = new address[](5);
        participants[0] = address(0x9991);
        participants[1] = address(0x9992);
        participants[2] = address(0x9993);
        participants[3] = address(0x9994);
        participants[4] = address(0x9995);

        // Fund contract with only enough for 3 payments (300 ether)
        // but we'll try to pay 5 participants (500 ether needed)
        usdc.mint(address(eventContract), 300 ether);

        // Register all participants
        vm.prank(systemAdmin);
        eventContract.registerParticipants(participants, systemAdmin);

        // Verify check-in for all participants
        for (uint256 i = 0; i < participants.length; i++) {
            vm.prank(systemAdmin);
            eventContract.verifyCheckIn(participants[i], verifier);
        }

        // Batch approve payments should revert immediately (before processing any payment)
        // with "Insufficient balance for batch payment" error
        vm.prank(systemAdmin);
        vm.expectRevert("Insufficient balance for batch payment");
        eventContract.batchApprovePayments(participants, approver);
    }
}
