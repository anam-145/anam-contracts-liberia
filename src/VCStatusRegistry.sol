// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract VCStatusRegistry is Ownable {
    enum VCStatus {
        NULL,
        ACTIVE,
        REVOKED,
        SUSPENDED
    }

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    mapping(bytes32 => mapping(address => bool)) public roles;
    mapping(string => VCStatus) public vcStatus;
    mapping(string => uint256) public revokedAt;

    event VCRegistered(string indexed vcId);
    event VCRevoked(string indexed vcId, uint256 timestamp);
    event VCSuspended(string indexed vcId);
    event VCActivated(string indexed vcId);

    modifier onlyRole(bytes32 role) {
        require(roles[role][msg.sender], "AccessControl: account is missing role");
        _;
    }

    constructor() Ownable(msg.sender) {
        roles[ISSUER_ROLE][msg.sender] = true;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }

    function grantRole(bytes32 role, address account) public onlyOwner {
        roles[role][account] = true;
    }

    function revokeRole(bytes32 role, address account) public onlyOwner {
        roles[role][account] = false;
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
