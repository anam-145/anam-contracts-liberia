// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract LiberiaEvent is AccessControl {
    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    address public usdcAddress;
    uint256 public startTime;
    uint256 public endTime;
    uint256 public amountPerDay;
    uint256 public maxParticipants;
    uint256 public maxTotalPayments;

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

        for (uint256 i = 0; i < _approvers.length; i++) {
            _grantRole(APPROVER_ROLE, _approvers[i]);
        }
        for (uint256 i = 0; i < _verifiers.length; i++) {
            _grantRole(VERIFIER_ROLE, _verifiers[i]);
        }
    }
}
