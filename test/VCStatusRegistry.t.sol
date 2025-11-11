// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/VCStatusRegistry.sol";

contract VCStatusRegistryTest is Test {
    VCStatusRegistry public registry;
    address public deployer;
    address public nonIssuer;

    event VCRegistered(string indexed vcId);
    event VCRevoked(string indexed vcId, uint256 timestamp);
    event VCSuspended(string indexed vcId);
    event VCActivated(string indexed vcId);

    function setUp() public {
        deployer = address(this);
        nonIssuer = address(0x1234);
        registry = new VCStatusRegistry();
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

    function test_VCStatusEnumIsDefined() public pure {
        VCStatusRegistry.VCStatus status;

        status = VCStatusRegistry.VCStatus.NULL;
        assertEq(uint8(status), 0, "NULL should be 0");

        status = VCStatusRegistry.VCStatus.ACTIVE;
        assertEq(uint8(status), 1, "ACTIVE should be 1");

        status = VCStatusRegistry.VCStatus.REVOKED;
        assertEq(uint8(status), 2, "REVOKED should be 2");

        status = VCStatusRegistry.VCStatus.SUSPENDED;
        assertEq(uint8(status), 3, "SUSPENDED should be 3");
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

    function test_RegisterVCRevertsForNonIssuer() public {
        string memory vcId = "vc_kyc_12345";

        vm.prank(nonIssuer);
        vm.expectRevert();
        registry.registerVC(vcId);
    }

    function test_RegisterVCAcceptsValidParameters() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        assertTrue(true, "registerVC should accept valid vcId parameter");
    }

    function test_RegisterVCSetsStatusToActive() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        VCStatusRegistry.VCStatus status = registry.vcStatus(vcId);
        assertEq(
            uint8(status), uint8(VCStatusRegistry.VCStatus.ACTIVE), "VC status should be ACTIVE after registration"
        );
    }

    function test_RegisterVCEmitsVCRegisteredEvent() public {
        string memory vcId = "vc_kyc_12345";

        vm.expectEmit(true, true, true, true);
        emit VCRegistered(vcId);

        registry.registerVC(vcId);
    }

    function test_RegisterVCRevertsWhenRegisteringSameVCIdTwice() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        vm.expectRevert();
        registry.registerVC(vcId);
    }

    function test_RevokeVCRevertsForNonIssuer() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        vm.prank(nonIssuer);
        vm.expectRevert();
        registry.revokeVC(vcId);
    }

    function test_RevokeVCAcceptsValidParameters() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.revokeVC(vcId);

        assertTrue(true, "revokeVC should accept valid vcId parameter");
    }

    function test_RevokeVCChangesStatusFromActiveToRevoked() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        VCStatusRegistry.VCStatus statusBefore = registry.vcStatus(vcId);
        assertEq(
            uint8(statusBefore), uint8(VCStatusRegistry.VCStatus.ACTIVE), "VC status should be ACTIVE before revocation"
        );

        registry.revokeVC(vcId);

        VCStatusRegistry.VCStatus statusAfter = registry.vcStatus(vcId);
        assertEq(
            uint8(statusAfter), uint8(VCStatusRegistry.VCStatus.REVOKED), "VC status should be REVOKED after revocation"
        );
    }

    function test_RevokeVCRecordsRevocationTimestamp() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        uint256 timestampBefore = block.timestamp;
        registry.revokeVC(vcId);
        uint256 timestampAfter = block.timestamp;

        uint256 revokedAt = registry.revokedAt(vcId);
        assertTrue(
            revokedAt >= timestampBefore && revokedAt <= timestampAfter, "Revocation timestamp should be recorded"
        );
        assertEq(revokedAt, block.timestamp, "Revocation timestamp should match block.timestamp");
    }

    function test_RevokeVCEmitsVCRevokedEvent() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        vm.expectEmit(true, true, true, true);
        emit VCRevoked(vcId, block.timestamp);

        registry.revokeVC(vcId);
    }

    function test_RevokeVCRevertsWhenRevokingUnregisteredVC() public {
        string memory vcId = "vc_kyc_unregistered";

        vm.expectRevert();
        registry.revokeVC(vcId);
    }

    function test_RevokeVCRevertsWhenRevokingAlreadyRevokedVC() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.revokeVC(vcId);

        VCStatusRegistry.VCStatus status = registry.vcStatus(vcId);
        assertEq(uint8(status), uint8(VCStatusRegistry.VCStatus.REVOKED), "VC should be REVOKED");

        vm.expectRevert();
        registry.revokeVC(vcId);
    }

    function test_GetVCStatusReturnsNullForUnregisteredVCId() public view {
        string memory vcId = "vc_kyc_unregistered";

        VCStatusRegistry.VCStatus status = registry.vcStatus(vcId);
        assertEq(uint8(status), uint8(VCStatusRegistry.VCStatus.NULL), "Status should be NULL for unregistered vcId");
    }

    function test_GetVCStatusReturnsActiveForRegisteredVCId() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        VCStatusRegistry.VCStatus status = registry.vcStatus(vcId);
        assertEq(uint8(status), uint8(VCStatusRegistry.VCStatus.ACTIVE), "Status should be ACTIVE for registered vcId");
    }

    function test_GetVCStatusReturnsRevokedForRevokedVCId() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.revokeVC(vcId);

        VCStatusRegistry.VCStatus status = registry.vcStatus(vcId);
        assertEq(uint8(status), uint8(VCStatusRegistry.VCStatus.REVOKED), "Status should be REVOKED for revoked vcId");
    }

    function test_GetVCStatusIsCallableByAnyone() public {
        string memory vcId = "vc_kyc_12345";
        address anyUser = address(0x9999);

        registry.registerVC(vcId);

        vm.prank(anyUser);
        VCStatusRegistry.VCStatus status = registry.vcStatus(vcId);
        assertEq(uint8(status), uint8(VCStatusRegistry.VCStatus.ACTIVE), "Anyone should be able to query VC status");
    }

    function test_GetRevokedAtReturnsCorrectTimestampForRevokedVC() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        uint256 expectedTimestamp = block.timestamp;
        registry.revokeVC(vcId);

        uint256 actualTimestamp = registry.revokedAt(vcId);
        assertEq(actualTimestamp, expectedTimestamp, "revokedAt should return correct timestamp for revoked VC");
    }

    function test_GetRevokedAtReturns0ForNonRevokedVC() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        uint256 timestamp = registry.revokedAt(vcId);
        assertEq(timestamp, 0, "revokedAt should return 0 for non-revoked VC");
    }

    function test_SuspendVCRevertsForNonIssuer() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        vm.prank(nonIssuer);
        vm.expectRevert();
        registry.suspendVC(vcId);
    }

    function test_SuspendVCChangesStatusFromActiveToSuspended() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        VCStatusRegistry.VCStatus statusBefore = registry.vcStatus(vcId);
        assertEq(
            uint8(statusBefore), uint8(VCStatusRegistry.VCStatus.ACTIVE), "VC status should be ACTIVE before suspension"
        );

        registry.suspendVC(vcId);

        VCStatusRegistry.VCStatus statusAfter = registry.vcStatus(vcId);
        assertEq(
            uint8(statusAfter),
            uint8(VCStatusRegistry.VCStatus.SUSPENDED),
            "VC status should be SUSPENDED after suspension"
        );
    }

    function test_SuspendVCEmitsVCSuspendedEvent() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        vm.expectEmit(true, true, true, true);
        emit VCSuspended(vcId);

        registry.suspendVC(vcId);
    }

    function test_SuspendVCRevertsWhenSuspendingUnregisteredVC() public {
        string memory vcId = "vc_kyc_unregistered";

        vm.expectRevert();
        registry.suspendVC(vcId);
    }

    function test_SuspendVCRevertsWhenSuspendingRevokedVC() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.revokeVC(vcId);

        vm.expectRevert();
        registry.suspendVC(vcId);
    }

    function test_SuspendVCRevertsWhenSuspendingAlreadySuspendedVC() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.suspendVC(vcId);

        vm.expectRevert();
        registry.suspendVC(vcId);
    }

    function test_ActivateVCRevertsForNonIssuer() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.suspendVC(vcId);

        vm.prank(nonIssuer);
        vm.expectRevert();
        registry.activateVC(vcId);
    }

    function test_ActivateVCChangesStatusFromSuspendedToActive() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.suspendVC(vcId);

        VCStatusRegistry.VCStatus statusBefore = registry.vcStatus(vcId);
        assertEq(
            uint8(statusBefore),
            uint8(VCStatusRegistry.VCStatus.SUSPENDED),
            "VC status should be SUSPENDED before activation"
        );

        registry.activateVC(vcId);

        VCStatusRegistry.VCStatus statusAfter = registry.vcStatus(vcId);
        assertEq(
            uint8(statusAfter), uint8(VCStatusRegistry.VCStatus.ACTIVE), "VC status should be ACTIVE after activation"
        );
    }

    function test_ActivateVCEmitsVCActivatedEvent() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.suspendVC(vcId);

        vm.expectEmit(true, true, true, true);
        emit VCActivated(vcId);

        registry.activateVC(vcId);
    }

    function test_ActivateVCRevertsWhenActivatingUnregisteredVC() public {
        string memory vcId = "vc_kyc_unregistered";

        vm.expectRevert();
        registry.activateVC(vcId);
    }

    function test_ActivateVCRevertsWhenActivatingRevokedVC() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);
        registry.revokeVC(vcId);

        vm.expectRevert();
        registry.activateVC(vcId);
    }

    function test_ActivateVCRevertsWhenActivatingAlreadyActiveVC() public {
        string memory vcId = "vc_kyc_12345";

        registry.registerVC(vcId);

        vm.expectRevert();
        registry.activateVC(vcId);
    }

    function test_MultipleVCsCanBeRegisteredInSequence() public {
        string memory vc1 = "vc_kyc_1";
        string memory vc2 = "vc_kyc_2";
        string memory vc3 = "vc_kyc_3";

        registry.registerVC(vc1);
        registry.registerVC(vc2);
        registry.registerVC(vc3);

        assertEq(uint8(registry.vcStatus(vc1)), uint8(VCStatusRegistry.VCStatus.ACTIVE), "First VC should be ACTIVE");
        assertEq(uint8(registry.vcStatus(vc2)), uint8(VCStatusRegistry.VCStatus.ACTIVE), "Second VC should be ACTIVE");
        assertEq(uint8(registry.vcStatus(vc3)), uint8(VCStatusRegistry.VCStatus.ACTIVE), "Third VC should be ACTIVE");
    }

    function test_RegisterVCRevertsWhenVCIdIsEmpty() public {
        string memory emptyVCId = "";

        vm.expectRevert();
        registry.registerVC(emptyVCId);
    }
}
