// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MonadSecurityAttestation
 * @dev Cryptographic Security Report Attestation Contract for GARUDA-X on Monad Testnet (Chain ID 10143).
 * Records SHA-256 security report hashes, risk scores, device counts, and timestamps on-chain.
 */
contract MonadSecurityAttestation {
    struct Attestation {
        bytes32 reportHash;
        uint256 riskScore;
        uint256 deviceCount;
        uint256 timestamp;
        address submitter;
    }

    Attestation[] public attestations;
    mapping(bytes32 => bool) public isReportAttested;

    event SecurityAttestationMinted(
        uint256 indexed attestationId,
        bytes32 indexed reportHash,
        uint256 riskScore,
        uint256 deviceCount,
        uint256 timestamp,
        address submitter
    );

    function mintAttestation(bytes32 reportHash, uint256 riskScore, uint256 deviceCount) external returns (uint256) {
        require(reportHash != bytes32(0), "Invalid report hash");
        require(!isReportAttested[reportHash], "Report hash already attested");

        attestations.push(Attestation({
            reportHash: reportHash,
            riskScore: riskScore,
            deviceCount: deviceCount,
            timestamp: block.timestamp,
            submitter: msg.sender
        }));

        isReportAttested[reportHash] = true;
        uint256 attestationId = attestations.length - 1;

        emit SecurityAttestationMinted(attestationId, reportHash, riskScore, deviceCount, block.timestamp, msg.sender);
        return attestationId;
    }

    function getAttestationCount() external view returns (uint256) {
        return attestations.length;
    }

    function getAttestation(uint256 index) external view returns (
        bytes32 reportHash,
        uint256 riskScore,
        uint256 deviceCount,
        uint256 timestamp,
        address submitter
    ) {
        require(index < attestations.length, "Index out of bounds");
        Attestation memory att = attestations[index];
        return (att.reportHash, att.riskScore, att.deviceCount, att.timestamp, att.submitter);
    }
}
