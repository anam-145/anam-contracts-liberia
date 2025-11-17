// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract EventFactory is AccessControl {
    address public usdcAddress;

    constructor(address _usdcAddress) {
        require(_usdcAddress != address(0), "Invalid USDC address");
        usdcAddress = _usdcAddress;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function createEvent(
        uint256 startTime,
        uint256 endTime,
        uint256 amountPerDay,
        uint256 maxParticipants,
        uint256 maxTotalPayments,
        address[] memory /* approvers */,
        address[] memory /* verifiers */
    ) external pure returns (address) {
        require(endTime > startTime, "Invalid time range");
        require(amountPerDay > 0, "Invalid amount per day");
        require(maxParticipants > 0, "Invalid max participants");
        require(maxTotalPayments > 0, "Invalid max total payments");
        return address(0);
    }
}
