// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SheShieldAnchor
/// @notice Stores SHA-256 evidence-vault fingerprints with the time and sender of each anchor.
/// @dev Only a 32-byte fingerprint is stored. No evidence, text, names or identifiers ever go on-chain.
///      Anchoring proves a fingerprint existed no later than the block timestamp. It does not prove
///      who wrote a message or that its content is true.
contract SheShieldAnchor {
    struct Anchor {
        address anchorer;
        uint64 timestamp;
        uint64 blockNumber;
    }

    mapping(bytes32 => Anchor) private anchors;       // fingerprint -> first anchor
    mapping(address => bytes32) public latestOf;      // anchoring wallet -> its most recent fingerprint

    event Anchored(address indexed anchorer, bytes32 indexed fingerprint, uint64 timestamp);

    error AlreadyAnchored();
    error EmptyFingerprint();

    /// @notice Record a fingerprint. Reverts if this exact fingerprint was already recorded.
    function anchor(bytes32 fingerprint) external {
        if (fingerprint == bytes32(0)) revert EmptyFingerprint();
        if (anchors[fingerprint].timestamp != 0) revert AlreadyAnchored();
        anchors[fingerprint] = Anchor(msg.sender, uint64(block.timestamp), uint64(block.number));
        latestOf[msg.sender] = fingerprint;
        emit Anchored(msg.sender, fingerprint, uint64(block.timestamp));
    }

    /// @notice Look up a fingerprint. exists is false when it was never anchored.
    function getAnchor(bytes32 fingerprint)
        external
        view
        returns (bool exists, address anchorer, uint64 timestamp, uint64 blockNumber)
    {
        Anchor memory a = anchors[fingerprint];
        return (a.timestamp != 0, a.anchorer, a.timestamp, a.blockNumber);
    }
}
