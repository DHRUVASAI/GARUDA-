// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MonadSecurityAttestation
 * @notice High-throughput, sub-second Merkle root attestation contract for GARUDA v8 on Monad EVM.
 */
contract MonadSecurityAttestation {
    struct AttestationBatch {
        bytes32 merkleRoot;
        uint64 blockHeight;
        uint32 eventCount;
        uint64 anchoredAt;
        address reporter;
    }

    mapping(bytes32 => AttestationBatch) public batches;
    bytes32[] public rootHistory;

    event SecurityBatchAnchored(
        bytes32 indexed merkleRoot,
        uint64 indexed blockHeight,
        uint32 eventCount,
        address indexed reporter,
        uint64 anchoredAt
    );

    function anchorBatch(bytes32 merkleRoot, uint64 blockHeight, uint32 eventCount) external {
        require(merkleRoot != bytes32(0), "Invalid merkleRoot");
        require(batches[merkleRoot].anchoredAt == 0, "Root already anchored");

        uint64 ts = uint64(block.timestamp);
        batches[merkleRoot] = AttestationBatch({
            merkleRoot: merkleRoot,
            blockHeight: blockHeight,
            eventCount: eventCount,
            anchoredAt: ts,
            reporter: msg.sender
        });
        rootHistory.push(merkleRoot);

        emit SecurityBatchAnchored(merkleRoot, blockHeight, eventCount, msg.sender, ts);
    }

    function totalAnchoredBatches() external view returns (uint256) {
        return rootHistory.length;
    }
}
