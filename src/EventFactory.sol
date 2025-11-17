// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {LiberiaEvent} from "./LiberiaEvent.sol";

contract EventFactory is AccessControl {
    bytes32 public constant SYSTEM_ADMIN_ROLE = keccak256("SYSTEM_ADMIN_ROLE");

    address public usdcAddress;
    address[] public events;

    event EventCreated(address indexed eventAddress, address indexed creator);

    constructor(address _usdcAddress) {
        require(_usdcAddress != address(0), "Invalid USDC address");
        usdcAddress = _usdcAddress;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SYSTEM_ADMIN_ROLE, msg.sender);
    }

    function createEvent(
        uint256 startTime,
        uint256 endTime,
        uint256 amountPerDay,
        uint256 maxParticipants,
        uint256 maxTotalPayments,
        address[] memory approvers,
        address[] memory verifiers
    ) external onlyRole(SYSTEM_ADMIN_ROLE) returns (address) {
        require(endTime > startTime, "Invalid time range");
        require(amountPerDay > 0, "Invalid amount per day");
        require(maxParticipants > 0, "Invalid max participants");
        require(maxTotalPayments > 0, "Invalid max total payments");

        LiberiaEvent newEvent = new LiberiaEvent(
            usdcAddress,
            startTime,
            endTime,
            amountPerDay,
            maxParticipants,
            maxTotalPayments,
            approvers,
            verifiers,
            msg.sender
        );

        address eventAddress = address(newEvent);
        events.push(eventAddress);
        emit EventCreated(eventAddress, msg.sender);

        return eventAddress;
    }

    function getEventsLength() external view returns (uint256) {
        return events.length;
    }
}
