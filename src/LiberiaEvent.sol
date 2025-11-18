// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract LiberiaEvent is AccessControl {
    enum ParticipantStatus {
        NULL,
        VERIFIED,
        COMPLETED
    }

    bytes32 public constant SYSTEM_ADMIN_ROLE = keccak256("SYSTEM_ADMIN_ROLE");
    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    address public usdcAddress;
    uint256 public startTime;
    uint256 public endTime;
    uint256 public amountPerDay;
    uint256 public maxParticipants;
    uint256 public maxTotalPayments;

    mapping(address => bool) public isParticipant;
    uint256 public participantCount;
    mapping(address => mapping(uint256 => ParticipantStatus)) private participantStatusForDay;
    mapping(address => uint256) private checkInCount;

    event ParticipantRegistered(address indexed participant, address indexed admin);
    event ParticipantRemoved(address indexed participant, address indexed admin);
    event CheckInVerified(address indexed participant, address indexed verifier, uint256 indexed day);

    constructor(
        address _usdcAddress,
        uint256 _startTime,
        uint256 _endTime,
        uint256 _amountPerDay,
        uint256 _maxParticipants,
        uint256 _maxTotalPayments,
        address[] memory _approvers,
        address[] memory _verifiers,
        address _systemAdmin
    ) {
        usdcAddress = _usdcAddress;
        startTime = _startTime;
        endTime = _endTime;
        amountPerDay = _amountPerDay;
        maxParticipants = _maxParticipants;
        maxTotalPayments = _maxTotalPayments;

        _grantRole(SYSTEM_ADMIN_ROLE, _systemAdmin);
        _setRoleAdmin(APPROVER_ROLE, SYSTEM_ADMIN_ROLE);
        _setRoleAdmin(VERIFIER_ROLE, SYSTEM_ADMIN_ROLE);

        for (uint256 i = 0; i < _approvers.length; i++) {
            _grantRole(APPROVER_ROLE, _approvers[i]);
        }
        for (uint256 i = 0; i < _verifiers.length; i++) {
            _grantRole(VERIFIER_ROLE, _verifiers[i]);
        }
    }

    function registerParticipant(address participant) external onlyRole(SYSTEM_ADMIN_ROLE) {
        _registerParticipant(participant);
    }

    function registerParticipants(address[] memory participants) external onlyRole(SYSTEM_ADMIN_ROLE) {
        for (uint256 i = 0; i < participants.length; i++) {
            _registerParticipant(participants[i]);
        }
    }

    function _registerParticipant(address participant) private {
        require(participant != address(0), "Invalid participant address");
        require(participantCount < maxParticipants, "Max participants reached");
        isParticipant[participant] = true;
        participantCount++;
        emit ParticipantRegistered(participant, msg.sender);
    }

    function removeParticipant(address participant) external onlyRole(SYSTEM_ADMIN_ROLE) {
        require(isParticipant[participant], "Participant not registered");
        isParticipant[participant] = false;
        participantCount--;
        emit ParticipantRemoved(participant, msg.sender);
    }

    function verifyCheckIn(address participant, address verifier, uint256 day) external onlyRole(SYSTEM_ADMIN_ROLE) {
        require(hasRole(VERIFIER_ROLE, verifier), "Verifier does not have VERIFIER_ROLE");
        require(isParticipant[participant], "Participant not registered");
        require(day >= startTime && day <= endTime, "Check-in outside event time range");

        uint256 normalizedDay = (day / 1 days) * 1 days;

        require(
            participantStatusForDay[participant][normalizedDay] == ParticipantStatus.NULL,
            "Participant already checked in for this day"
        );
        participantStatusForDay[participant][normalizedDay] = ParticipantStatus.VERIFIED;
        checkInCount[participant]++;
        emit CheckInVerified(participant, verifier, normalizedDay);
    }

    function isVerifiedForDay(address participant, uint256 day) external view returns (bool) {
        uint256 normalizedDay = (day / 1 days) * 1 days;
        return participantStatusForDay[participant][normalizedDay] == ParticipantStatus.VERIFIED;
    }

    function getParticipantStatusForDay(address participant, uint256 day) external view returns (ParticipantStatus) {
        uint256 normalizedDay = (day / 1 days) * 1 days;
        return participantStatusForDay[participant][normalizedDay];
    }

    function getCheckInCount(address participant) external view returns (uint256) {
        return checkInCount[participant];
    }
}
