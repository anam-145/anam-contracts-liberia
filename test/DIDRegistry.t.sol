// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/DIDRegistry.sol";

contract DIDRegistryTest is Test {
    DIDRegistry public registry;
    address public deployer;
    address public nonIssuer;

    event IdentityRegistered(address indexed userAddress, string indexed didString, bytes32 documentHash);

    function setUp() public {
        deployer = address(this);
        nonIssuer = address(0x1234);
        registry = new DIDRegistry();
    }

    function test_ContractDeploysSuccessfully() public view {
        assertTrue(address(registry) != address(0), "Contract should deploy successfully");
    }

    function test_IssuerRoleIsDefined() public view {
        bytes32 issuerRole = registry.ISSUER_ROLE();
        assertTrue(issuerRole != bytes32(0), "ISSUER_ROLE should be defined");
    }

    function test_DeployerHasIssuerRole() public view {
        bool hasRole = registry.hasRole(registry.ISSUER_ROLE(), deployer);
        assertTrue(hasRole, "Deployer should have ISSUER_ROLE");
    }

    function test_RegisterIdentityRevertsForNonIssuer() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        vm.prank(nonIssuer);
        vm.expectRevert();
        registry.registerIdentity(userAddress, didString, documentHash);
    }

    function test_RegisterIdentityAcceptsValidParameters() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress, didString, documentHash);

        assertTrue(true, "registerIdentity should accept valid parameters");
    }

    function test_RegisterIdentityStoresAddressToDIDMapping() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress, didString, documentHash);

        string memory storedDID = registry.addressToDID(userAddress);
        assertEq(storedDID, didString, "Address to DID mapping should be stored correctly");
    }

    function test_RegisterIdentityStoresDIDToAddressReverseMapping() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress, didString, documentHash);

        address storedAddress = registry.didToAddress(didString);
        assertEq(storedAddress, userAddress, "DID to address reverse mapping should be stored correctly");
    }

    function test_RegisterIdentityStoresDIDToDocumentHashMapping() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress, didString, documentHash);

        bytes32 storedHash = registry.didToDocumentHash(didString);
        assertEq(storedHash, documentHash, "DID to document hash mapping should be stored correctly");
    }

    function test_RegisterIdentityEmitsIdentityRegisteredEvent() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        vm.expectEmit(true, true, true, true);
        emit IdentityRegistered(userAddress, didString, documentHash);

        registry.registerIdentity(userAddress, didString, documentHash);
    }

    function test_RegisterIdentityRevertsWhenRegisteringSameAddressTwice() public {
        address userAddress = address(0x5678);
        string memory didString1 = "did:anam:undp-lr:user:12345";
        string memory didString2 = "did:anam:undp-lr:user:67890";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress, didString1, documentHash);

        vm.expectRevert();
        registry.registerIdentity(userAddress, didString2, documentHash);
    }

    function test_RegisterIdentityRevertsWhenRegisteringSameDIDTwice() public {
        address userAddress1 = address(0x5678);
        address userAddress2 = address(0x9ABC);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress1, didString, documentHash);

        vm.expectRevert();
        registry.registerIdentity(userAddress2, didString, documentHash);
    }

    function test_RegisterIdentityRevertsWhenRegisteringSameDocumentHashTwice() public {
        address userAddress1 = address(0x5678);
        address userAddress2 = address(0x9ABC);
        string memory didString1 = "did:anam:undp-lr:user:12345";
        string memory didString2 = "did:anam:undp-lr:user:67890";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress1, didString1, documentHash);

        vm.expectRevert();
        registry.registerIdentity(userAddress2, didString2, documentHash);
    }

    function test_GetDIDByAddressReturnsCorrectDIDForRegisteredAddress() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress, didString, documentHash);

        string memory retrievedDID = registry.addressToDID(userAddress);
        assertEq(retrievedDID, didString, "Should return correct DID for registered address");
    }

    function test_GetDIDByAddressReturnsEmptyStringForUnregisteredAddress() public view {
        address unregisteredAddress = address(0xDEADBEEF);

        string memory retrievedDID = registry.addressToDID(unregisteredAddress);
        assertEq(bytes(retrievedDID).length, 0, "Should return empty string for unregistered address");
    }

    function test_GetAddressByDIDReturnsCorrectAddressForRegisteredDID() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress, didString, documentHash);

        address retrievedAddress = registry.didToAddress(didString);
        assertEq(retrievedAddress, userAddress, "Should return correct address for registered DID");
    }

    function test_GetAddressByDIDReturnsZeroAddressForUnregisteredDID() public view {
        string memory unregisteredDID = "did:anam:undp-lr:user:99999";

        address retrievedAddress = registry.didToAddress(unregisteredDID);
        assertEq(retrievedAddress, address(0), "Should return zero address for unregistered DID");
    }

    function test_GetDocumentHashReturnsCorrectHashForRegisteredDID() public {
        address userAddress = address(0x5678);
        string memory didString = "did:anam:undp-lr:user:12345";
        bytes32 documentHash = keccak256("document");

        registry.registerIdentity(userAddress, didString, documentHash);

        bytes32 retrievedHash = registry.didToDocumentHash(didString);
        assertEq(retrievedHash, documentHash, "Should return correct document hash for registered DID");
    }

    function test_GetDocumentHashReturnsZeroBytes32ForUnregisteredDID() public view {
        string memory unregisteredDID = "did:anam:undp-lr:user:99999";

        bytes32 retrievedHash = registry.didToDocumentHash(unregisteredDID);
        assertEq(retrievedHash, bytes32(0), "Should return zero bytes32 for unregistered DID");
    }

    function test_ContractInheritsFromOwnable() public view {
        address owner = registry.owner();
        assertTrue(owner != address(0), "Contract should have an owner");
    }

    function test_DeployerIsInitialOwner() public view {
        address owner = registry.owner();
        assertEq(owner, deployer, "Deployer should be the initial owner");
    }

    function test_OwnerCanGrantIssuerRole() public {
        address newIssuer = address(0xABCD);

        assertFalse(
            registry.hasRole(registry.ISSUER_ROLE(), newIssuer), "New address should not have ISSUER role initially"
        );

        registry.grantRole(registry.ISSUER_ROLE(), newIssuer);

        assertTrue(
            registry.hasRole(registry.ISSUER_ROLE(), newIssuer), "New address should have ISSUER role after granting"
        );
    }

    function test_OwnerCanRevokeIssuerRole() public {
        address issuer = address(0xABCD);

        registry.grantRole(registry.ISSUER_ROLE(), issuer);
        assertTrue(registry.hasRole(registry.ISSUER_ROLE(), issuer), "Address should have ISSUER role after granting");

        registry.revokeRole(registry.ISSUER_ROLE(), issuer);

        assertFalse(
            registry.hasRole(registry.ISSUER_ROLE(), issuer), "Address should not have ISSUER role after revoking"
        );
    }

    function test_NonOwnerCannotGrantIssuerRole() public {
        address newIssuer = address(0xABCD);
        bytes32 issuerRole = registry.ISSUER_ROLE();

        vm.prank(nonIssuer);
        vm.expectRevert();
        registry.grantRole(issuerRole, newIssuer);
    }

    function test_NonOwnerCannotRevokeIssuerRole() public {
        address issuer = address(0xABCD);
        bytes32 issuerRole = registry.ISSUER_ROLE();

        registry.grantRole(issuerRole, issuer);
        assertTrue(registry.hasRole(issuerRole, issuer), "Address should have ISSUER role");

        vm.prank(nonIssuer);
        vm.expectRevert();
        registry.revokeRole(issuerRole, issuer);

        assertTrue(registry.hasRole(issuerRole, issuer), "Address should still have ISSUER role after failed revoke");
    }

    function test_MultipleDIDsCanBeRegisteredInSequence() public {
        address user1 = address(0x1111);
        address user2 = address(0x2222);
        address user3 = address(0x3333);

        string memory did1 = "did:anam:undp-lr:user:1";
        string memory did2 = "did:anam:undp-lr:user:2";
        string memory did3 = "did:anam:undp-lr:user:3";

        bytes32 hash1 = keccak256("doc1");
        bytes32 hash2 = keccak256("doc2");
        bytes32 hash3 = keccak256("doc3");

        registry.registerIdentity(user1, did1, hash1);
        registry.registerIdentity(user2, did2, hash2);
        registry.registerIdentity(user3, did3, hash3);

        assertEq(registry.addressToDID(user1), did1, "First DID should be registered correctly");
        assertEq(registry.addressToDID(user2), did2, "Second DID should be registered correctly");
        assertEq(registry.addressToDID(user3), did3, "Third DID should be registered correctly");

        assertEq(registry.didToAddress(did1), user1, "First reverse mapping should work");
        assertEq(registry.didToAddress(did2), user2, "Second reverse mapping should work");
        assertEq(registry.didToAddress(did3), user3, "Third reverse mapping should work");
    }
}
