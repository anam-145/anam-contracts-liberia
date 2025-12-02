// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract DIDRegistry is AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    mapping(address => string) public addressToDID;
    mapping(string => address) public didToAddress;
    mapping(string => bytes32) public didToDocumentHash;
    mapping(bytes32 => bool) public documentHashExists;

    event IdentityRegistered(address indexed userAddress, string indexed didString, bytes32 documentHash);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ISSUER_ROLE, msg.sender);
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
