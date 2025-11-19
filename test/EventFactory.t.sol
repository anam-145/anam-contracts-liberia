// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {EventFactory} from "../src/EventFactory.sol";
import {LiberiaEvent} from "../src/LiberiaEvent.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

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
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectRevert("Invalid time range");
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);
    }

    function test_RevertWhenCreatingEventWithZeroAmountPerDay() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 0; // Zero amount
        uint256 maxParticipants = 50;

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectRevert("Invalid amount per day");
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);
    }

    function test_RevertWhenCreatingEventWithZeroMaxParticipants() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 0; // Zero max participants

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectRevert("Invalid max participants");
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);
    }

    function test_CreateNewEventContractWithValidParameters() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address eventAddress =
            factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);

        assertTrue(eventAddress != address(0));
    }

    function test_EmitEventCreatedEventWhenEventIsCreated() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        vm.expectEmit(false, true, false, false);
        emit EventCreated(address(0), deployer);

        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);
    }

    event EventCreated(address indexed eventAddress, address indexed creator);

    function test_StoreCreatedEventAddressInEventsArray() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address eventAddress =
            factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);

        assertEq(factory.getEventsLength(), 1);
        assertEq(factory.events(0), eventAddress);
    }

    function test_AssignApproversToTheCreatedEventContract() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;

        address[] memory approvers = new address[](2);
        approvers[0] = address(0x1111);
        approvers[1] = address(0x2222);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x3333);

        address eventAddress =
            factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);

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

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](2);
        verifiers[0] = address(0x2222);
        verifiers[1] = address(0x3333);

        address eventAddress =
            factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);

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
        address eventAddress =
            factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);

        assertTrue(eventAddress != address(0));
    }

    function test_RevertWhenNonAdminTriesToCreateEvent() public {
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        // Try to create event as non-admin
        address nonAdmin = address(0x8888);

        vm.prank(nonAdmin);
        vm.expectRevert();
        factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);
    }

    function test_CreateMultipleEventsIndependently() public {
        address[] memory approvers1 = new address[](1);
        approvers1[0] = address(0x1111);
        address[] memory verifiers1 = new address[](1);
        verifiers1[0] = address(0x2222);

        address eventAddress1 =
            factory.createEvent(block.timestamp, block.timestamp + 7 days, 100 ether, 50, approvers1, verifiers1);

        address[] memory approvers2 = new address[](1);
        approvers2[0] = address(0x3333);
        address[] memory verifiers2 = new address[](1);
        verifiers2[0] = address(0x4444);

        address eventAddress2 = factory.createEvent(
            block.timestamp + 1 days, block.timestamp + 14 days, 200 ether, 100, approvers2, verifiers2
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

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address returnedAddress =
            factory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);

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

    function test_CompleteFullFlowCreateEventRegisterVerifyApprove() public {
        // Integration test: Full flow from event creation to payment approval

        // Step 0: Deploy a mock USDC token and create factory with it
        MockUSDC usdc = new MockUSDC();
        EventFactory testFactory = new EventFactory(address(usdc));

        // Step 1: Create event via factory
        uint256 startTime = block.timestamp;
        uint256 endTime = block.timestamp + 7 days;
        uint256 amountPerDay = 100 ether;
        uint256 maxParticipants = 50;

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address eventAddress =
            testFactory.createEvent(startTime, endTime, amountPerDay, maxParticipants, approvers, verifiers);

        LiberiaEvent eventContract = LiberiaEvent(eventAddress);

        // Verify event was created with correct USDC address
        assertEq(eventContract.usdcAddress(), address(usdc));

        // Step 2: Register participant
        address participant = address(0x3333);
        eventContract.registerParticipant(participant, address(this));

        // Verify participant is registered
        assertTrue(eventContract.isParticipant(participant));
        assertEq(eventContract.participantCount(), 1);

        // Step 3: Verify check-in
        uint256 checkInDay = block.timestamp;
        eventContract.verifyCheckIn(participant, verifiers[0]);

        // Verify check-in was recorded
        assertEq(eventContract.getCheckInCount(participant), 1);
        assertTrue(eventContract.isVerifiedForDay(participant, checkInDay));

        // Step 4: Fund contract with USDC
        usdc.transfer(eventAddress, 1000 ether);

        // Verify contract has balance
        assertEq(usdc.balanceOf(eventAddress), 1000 ether);

        // Step 5: Approve payment
        uint256 participantBalanceBefore = usdc.balanceOf(participant);
        eventContract.approvePayment(participant, approvers[0]);

        // Verify payment was made
        assertEq(usdc.balanceOf(participant), participantBalanceBefore + amountPerDay);
        assertEq(eventContract.getPaymentCount(participant), 1);

        // Verify participant status changed to COMPLETED
        LiberiaEvent.ParticipantStatus status = eventContract.getParticipantStatusForDay(participant, checkInDay);
        assertTrue(status == LiberiaEvent.ParticipantStatus.COMPLETED);
    }

    function test_HandleMultipleParticipantsInSameEvent() public {
        // Integration test: Multiple participants in the same event

        // Setup: Create USDC token and factory
        MockUSDC usdc = new MockUSDC();
        EventFactory testFactory = new EventFactory(address(usdc));

        // Create event
        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address eventAddress =
            testFactory.createEvent(block.timestamp, block.timestamp + 7 days, 100 ether, 50, approvers, verifiers);

        LiberiaEvent eventContract = LiberiaEvent(eventAddress);

        // Register 3 participants
        address participant1 = address(0x3333);
        address participant2 = address(0x4444);
        address participant3 = address(0x5555);

        eventContract.registerParticipant(participant1, address(this));
        eventContract.registerParticipant(participant2, address(this));
        eventContract.registerParticipant(participant3, address(this));

        // Verify all participants are registered
        assertEq(eventContract.participantCount(), 3);

        // Verify check-ins for all participants
        uint256 checkInDay = block.timestamp;
        eventContract.verifyCheckIn(participant1, verifiers[0]);
        eventContract.verifyCheckIn(participant2, verifiers[0]);
        eventContract.verifyCheckIn(participant3, verifiers[0]);

        // Verify all check-ins were recorded
        assertEq(eventContract.getCheckInCount(participant1), 1);
        assertEq(eventContract.getCheckInCount(participant2), 1);
        assertEq(eventContract.getCheckInCount(participant3), 1);

        // Fund contract and approve payments
        usdc.transfer(eventAddress, 1000 ether);

        eventContract.approvePayment(participant1, approvers[0]);
        eventContract.approvePayment(participant2, approvers[0]);
        eventContract.approvePayment(participant3, approvers[0]);

        // Verify all payments were made correctly (each should have 100 ether)
        assertEq(usdc.balanceOf(participant1), 100 ether);
        assertEq(usdc.balanceOf(participant2), 100 ether);
        assertEq(usdc.balanceOf(participant3), 100 ether);

        // Verify payment counts
        assertEq(eventContract.getPaymentCount(participant1), 1);
        assertEq(eventContract.getPaymentCount(participant2), 1);
        assertEq(eventContract.getPaymentCount(participant3), 1);

        // Verify all statuses are COMPLETED
        assertTrue(
            eventContract.getParticipantStatusForDay(participant1, checkInDay)
                == LiberiaEvent.ParticipantStatus.COMPLETED
        );
        assertTrue(
            eventContract.getParticipantStatusForDay(participant2, checkInDay)
                == LiberiaEvent.ParticipantStatus.COMPLETED
        );
        assertTrue(
            eventContract.getParticipantStatusForDay(participant3, checkInDay)
                == LiberiaEvent.ParticipantStatus.COMPLETED
        );

        // Verify contract balance was reduced correctly
        assertEq(usdc.balanceOf(eventAddress), 700 ether);
    }

    function test_HandleMultipleDaysSessionsCorrectly() public {
        // Integration test: Same participant across multiple days

        // Setup
        MockUSDC usdc = new MockUSDC();
        EventFactory testFactory = new EventFactory(address(usdc));

        address[] memory approvers = new address[](1);
        approvers[0] = address(0x1111);
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0x2222);

        address eventAddress =
            testFactory.createEvent(block.timestamp, block.timestamp + 7 days, 100 ether, 50, approvers, verifiers);

        LiberiaEvent eventContract = LiberiaEvent(eventAddress);

        // Register one participant
        address participant = address(0x3333);
        eventContract.registerParticipant(participant, address(this));

        // Fund contract with sufficient USDC
        usdc.transfer(eventAddress, 1000 ether);

        // Day 1: Check-in and payment
        uint256 day1 = block.timestamp;
        eventContract.verifyCheckIn(participant, verifiers[0]);
        eventContract.approvePayment(participant, approvers[0]);

        // Verify Day 1 state
        assertEq(eventContract.getCheckInCount(participant), 1);
        assertEq(eventContract.getPaymentCount(participant), 1);
        assertEq(usdc.balanceOf(participant), 100 ether);
        assertTrue(
            eventContract.getParticipantStatusForDay(participant, day1) == LiberiaEvent.ParticipantStatus.COMPLETED
        );

        // Day 2: Check-in and payment
        vm.warp(day1 + 1 days);
        uint256 day2 = block.timestamp;
        eventContract.verifyCheckIn(participant, verifiers[0]);
        eventContract.approvePayment(participant, approvers[0]);

        // Verify Day 2 state
        assertEq(eventContract.getCheckInCount(participant), 2);
        assertEq(eventContract.getPaymentCount(participant), 2);
        assertEq(usdc.balanceOf(participant), 200 ether);
        assertTrue(
            eventContract.getParticipantStatusForDay(participant, day2) == LiberiaEvent.ParticipantStatus.COMPLETED
        );

        // Day 3: Check-in and payment
        vm.warp(day1 + 2 days);
        uint256 day3 = block.timestamp;
        eventContract.verifyCheckIn(participant, verifiers[0]);
        eventContract.approvePayment(participant, approvers[0]);

        // Verify Day 3 state
        assertEq(eventContract.getCheckInCount(participant), 3);
        assertEq(eventContract.getPaymentCount(participant), 3);
        assertEq(usdc.balanceOf(participant), 300 ether);
        assertTrue(
            eventContract.getParticipantStatusForDay(participant, day3) == LiberiaEvent.ParticipantStatus.COMPLETED
        );

        // Verify Day 1 status is still COMPLETED (not affected by later days)
        assertTrue(
            eventContract.getParticipantStatusForDay(participant, day1) == LiberiaEvent.ParticipantStatus.COMPLETED
        );

        // Verify Day 2 status is still COMPLETED
        assertTrue(
            eventContract.getParticipantStatusForDay(participant, day2) == LiberiaEvent.ParticipantStatus.COMPLETED
        );

        // Verify contract balance was reduced correctly
        assertEq(usdc.balanceOf(eventAddress), 700 ether);
    }

    function test_PreventCrossEventInterference() public {
        // Integration test: Verify Event A admin cannot affect Event B

        // Setup
        MockUSDC usdc = new MockUSDC();
        EventFactory testFactory = new EventFactory(address(usdc));

        // Create Event A
        address[] memory approversA = new address[](1);
        approversA[0] = address(0x1111);
        address[] memory verifiersA = new address[](1);
        verifiersA[0] = address(0x2222);

        address eventAddressA =
            testFactory.createEvent(block.timestamp, block.timestamp + 7 days, 100 ether, 50, approversA, verifiersA);

        // Create Event B with different approvers/verifiers
        address[] memory approversB = new address[](1);
        approversB[0] = address(0x3333);
        address[] memory verifiersB = new address[](1);
        verifiersB[0] = address(0x4444);

        address eventAddressB =
            testFactory.createEvent(block.timestamp, block.timestamp + 7 days, 200 ether, 30, approversB, verifiersB);

        LiberiaEvent eventA = LiberiaEvent(eventAddressA);
        LiberiaEvent eventB = LiberiaEvent(eventAddressB);

        // Verify events are different
        assertTrue(eventAddressA != eventAddressB);

        // Register participants in both events
        address participantA = address(0x5555);
        address participantB = address(0x6666);

        eventA.registerParticipant(participantA, address(this));
        eventB.registerParticipant(participantB, address(this));

        // Verify participants are only in their respective events
        assertTrue(eventA.isParticipant(participantA));
        assertFalse(eventA.isParticipant(participantB));
        assertFalse(eventB.isParticipant(participantA));
        assertTrue(eventB.isParticipant(participantB));

        // Verify participant counts are independent
        assertEq(eventA.participantCount(), 1);
        assertEq(eventB.participantCount(), 1);

        // Verify approvers/verifiers from Event A don't have roles in Event B
        assertFalse(eventB.hasRole(eventB.APPROVER_ROLE(), approversA[0]));
        assertFalse(eventB.hasRole(eventB.VERIFIER_ROLE(), verifiersA[0]));

        // Verify approvers/verifiers from Event B don't have roles in Event A
        assertFalse(eventA.hasRole(eventA.APPROVER_ROLE(), approversB[0]));
        assertFalse(eventA.hasRole(eventA.VERIFIER_ROLE(), verifiersB[0]));

        // Verify check-in in Event A doesn't affect Event B
        uint256 checkInDay = block.timestamp;
        eventA.verifyCheckIn(participantA, verifiersA[0]);

        assertEq(eventA.getCheckInCount(participantA), 1);
        assertEq(eventB.getCheckInCount(participantB), 0);

        // Verify payments in Event A don't affect Event B
        usdc.transfer(eventAddressA, 1000 ether);
        usdc.transfer(eventAddressB, 1000 ether);

        eventA.approvePayment(participantA, approversA[0]);

        // Participant A should have 100 ether from Event A
        assertEq(usdc.balanceOf(participantA), 100 ether);
        // Participant B should have 0 (no payment in Event B yet)
        assertEq(usdc.balanceOf(participantB), 0);

        // Event A balance should be reduced
        assertEq(usdc.balanceOf(eventAddressA), 900 ether);
        // Event B balance should be unchanged
        assertEq(usdc.balanceOf(eventAddressB), 1000 ether);

        // Verify payment counts are independent
        assertEq(eventA.getPaymentCount(participantA), 1);
        assertEq(eventB.getPaymentCount(participantB), 0);
    }
}

contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
