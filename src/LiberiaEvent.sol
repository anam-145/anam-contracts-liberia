// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract LiberiaEvent is AccessControl {
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

    event ParticipantRegistered(address indexed participant, address indexed admin);
    event ParticipantRemoved(address indexed participant, address indexed admin);

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

        _grantRole(DEFAULT_ADMIN_ROLE, _systemAdmin);
        _grantRole(SYSTEM_ADMIN_ROLE, _systemAdmin);

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
}
