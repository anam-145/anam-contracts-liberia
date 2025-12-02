// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract VCStatusRegistry is AccessControl {
    enum VCStatus {
        NULL,
        ACTIVE,
        REVOKED,
        SUSPENDED
    }

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    mapping(string => VCStatus) public vcStatus;
    mapping(string => uint256) public revokedAt;

    event VCRegistered(string indexed vcId);
    event VCRevoked(string indexed vcId, uint256 timestamp);
    event VCSuspended(string indexed vcId);
    event VCActivated(string indexed vcId);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ISSUER_ROLE, msg.sender);
    }

    function registerVC(string memory vcId) public onlyRole(ISSUER_ROLE) {
        require(bytes(vcId).length > 0, "VC ID cannot be empty");
        require(vcStatus[vcId] == VCStatus.NULL, "VC already registered");
        vcStatus[vcId] = VCStatus.ACTIVE;
        emit VCRegistered(vcId);
    }

    function revokeVC(string memory vcId) public onlyRole(ISSUER_ROLE) {
        require(vcStatus[vcId] != VCStatus.NULL, "VC not registered");
        require(vcStatus[vcId] != VCStatus.REVOKED, "VC already revoked");
        vcStatus[vcId] = VCStatus.REVOKED;
        revokedAt[vcId] = block.timestamp;
        emit VCRevoked(vcId, block.timestamp);
    }

    function suspendVC(string memory vcId) public onlyRole(ISSUER_ROLE) {
        require(vcStatus[vcId] != VCStatus.NULL, "VC not registered");
        require(vcStatus[vcId] != VCStatus.REVOKED, "VC already revoked");
        require(vcStatus[vcId] != VCStatus.SUSPENDED, "VC already suspended");
        vcStatus[vcId] = VCStatus.SUSPENDED;
        emit VCSuspended(vcId);
    }

    function activateVC(string memory vcId) public onlyRole(ISSUER_ROLE) {
        require(vcStatus[vcId] != VCStatus.NULL, "VC not registered");
        require(vcStatus[vcId] != VCStatus.REVOKED, "VC already revoked");
        require(vcStatus[vcId] == VCStatus.SUSPENDED, "VC must be suspended to activate");
        vcStatus[vcId] = VCStatus.ACTIVE;
        emit VCActivated(vcId);
    }
}
