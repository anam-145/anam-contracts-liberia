// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract DIDRegistry is Ownable {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    mapping(bytes32 => mapping(address => bool)) public roles;
    mapping(address => string) public addressToDID;
    mapping(string => address) public didToAddress;
    mapping(string => bytes32) public didToDocumentHash;
    mapping(bytes32 => bool) public documentHashExists;

    event IdentityRegistered(address indexed userAddress, string indexed didString, bytes32 documentHash);

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

    function registerIdentity(address userAddress, string memory didString, bytes32 documentHash)
        public
        onlyRole(ISSUER_ROLE)
    {
        require(userAddress != address(0), "User address cannot be zero address");
        require(bytes(didString).length > 0, "DID string cannot be empty");
        require(documentHash != bytes32(0), "Document hash cannot be zero");
        require(bytes(addressToDID[userAddress]).length == 0, "Address already registered");
        require(didToAddress[didString] == address(0), "DID already registered");
        require(!documentHashExists[documentHash], "Document hash already registered");

        addressToDID[userAddress] = didString;
        didToAddress[didString] = userAddress;
        didToDocumentHash[didString] = documentHash;
        documentHashExists[documentHash] = true;

        emit IdentityRegistered(userAddress, didString, documentHash);
    }
}
