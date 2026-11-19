// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title GarudaAttestation
 * @notice Tamper-proof on-chain Merkle root registry for GARUDA v4 forensic security logs.
 *         Stores ONLY cryptographic SHA-256 Merkle roots and counts — zero PII or local IPs on-chain.
 */
contract GarudaAttestation {
    struct AnchorRecord {
        address guardianNode;
        uint64 anchoredAt;
        uint32 incidentCount;
        string networkFingerprint;
        bool exists;
    }

    mapping(bytes32 => AnchorRecord) public anchors;
    bytes32[] public anchoredRoots;

    event RootAnchored(
        bytes32 indexed merkleRoot,
        address indexed guardianNode,
        uint32 incidentCount,
        string networkFingerprint,
        uint64 timestamp
    );

    /**
     * @notice Anchor a batched SHA-256 Merkle root of local GARUDA security blocks.
     */
    function anchorRoot(
        bytes32 merkleRoot,
        uint32 incidentCount,
        string calldata networkFingerprint
    ) external {
        require(merkleRoot != bytes32(0), "GARUDA: empty root");
        require(!anchors[merkleRoot].exists, "GARUDA: root already anchored");

        anchors[merkleRoot] = AnchorRecord({
            guardianNode: msg.sender,
            anchoredAt: uint64(block.timestamp),
            incidentCount: incidentCount,
            networkFingerprint: networkFingerprint,
            exists: true
        });
        anchoredRoots.push(merkleRoot);

        emit RootAnchored(
            merkleRoot,
            msg.sender,
            incidentCount,
            networkFingerprint,
            uint64(block.timestamp)
        );
    }

    /**
     * @notice Verify that a specific incident SHA-256 leaf belongs to an anchored Merkle root.
     * @param merkleRoot Previously anchored Merkle root.
     * @param leafHash   SHA-256 hash of the canonical incident payload JSON.
     * @param proof      Sibling hashes along the Merkle path.
     * @param isLeft     True if sibling at step i sits on the left side of the concatenation.
     */
    function verifyIncident(
        bytes32 merkleRoot,
        bytes32 leafHash,
        bytes32[] calldata proof,
        bool[] calldata isLeft
    ) external view returns (bool) {
        if (!anchors[merkleRoot].exists || proof.length != isLeft.length) {
            return false;
        }
        bytes32 computed = leafHash;
        for (uint256 i = 0; i < proof.length; i++) {
            if (isLeft[i]) {
                computed = sha256(abi.encodePacked(proof[i], computed));
            } else {
                computed = sha256(abi.encodePacked(computed, proof[i]));
            }
        }
        return computed == merkleRoot;
    }

    function totalAnchoredRoots() external view returns (uint256) {
        return anchoredRoots.length;
    }
}
