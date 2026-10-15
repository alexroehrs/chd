// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title On-chain storage baseline
/// @notice Stores the encrypted JSON document itself in contract storage and echoes it in an
///         event, as designs that keep records on the ledger do. Used only as an experimental
///         baseline for gas and latency comparisons.
contract OnChainBaseline {
    mapping(address => string) private _data;

    event JSONSaved(address indexed user, string jsonData);

    function saveJSON(string calldata jsonData) external {
        _data[msg.sender] = jsonData;
        emit JSONSaved(msg.sender, jsonData);
    }

    function getJSON() external view returns (string memory) {
        return _data[msg.sender];
    }
}
