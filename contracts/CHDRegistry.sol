// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Chained Health Data (CHD) registry
/// @notice Consent, integrity and audit layer for off-chain encrypted health records.
/// @dev No clinical data, ciphertext or personal identifier is ever written to the chain.
///      The chain keeps only (i) a SHA-256 digest of the encrypted envelope, (ii) the owner
///      and time-bound access grants, (iii) a public-key directory and (iv) an audit trail.
///      Accounts are pseudonyms: the events still reveal how many records an account owns
///      and which institutions were granted access, and when.
contract CHDRegistry {
    struct Record {
        address owner;
        bytes32 contentHash; // SHA-256 of the encrypted envelope stored off-chain
        uint64 createdAt;
        uint64 updatedAt;
        bool erased;
    }

    struct Grant {
        uint64 expiresAt;
        bool revoked;
    }

    /// @notice Consortium administrator (in production: a multisig or on-chain governance).
    address public immutable admin;

    /// @notice Healthcare institutions authorised by the consortium to receive grants.
    mapping(address => bool) public isInstitution;

    /// @notice X25519 encryption public key published by each participant.
    mapping(address => bytes32) public encryptionKey;

    mapping(bytes32 => Record) private _records;
    mapping(bytes32 => mapping(address => Grant)) private _grants;

    event InstitutionSet(address indexed institution, bool enabled);
    event EncryptionKeySet(address indexed account, bytes32 key);
    event RecordRegistered(bytes32 indexed recordId, address indexed owner);
    event RecordUpdated(bytes32 indexed recordId);
    event RecordErased(bytes32 indexed recordId);
    event AccessGranted(bytes32 indexed recordId, address indexed grantee, uint64 expiresAt);
    event AccessRevoked(bytes32 indexed recordId, address indexed grantee);
    event AccessLogged(bytes32 indexed recordId, address indexed accessor, bytes32 requestHash);

    error NotAdmin();
    error NotOwner();
    error RecordExists();
    error UnknownRecord();
    error RecordIsErased();
    error NotInstitution();
    error InvalidExpiry();
    error InvalidHash();
    error AccessDenied();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyOwner(bytes32 recordId) {
        Record storage r = _records[recordId];
        if (r.owner == address(0)) revert UnknownRecord();
        if (r.owner != msg.sender) revert NotOwner();
        if (r.erased) revert RecordIsErased();
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // ------------------------------------------------------------------ governance

    function setInstitution(address institution, bool enabled) external onlyAdmin {
        isInstitution[institution] = enabled;
        emit InstitutionSet(institution, enabled);
    }

    // ------------------------------------------------------------------ key directory

    function setEncryptionKey(bytes32 key) external {
        encryptionKey[msg.sender] = key;
        emit EncryptionKeySet(msg.sender, key);
    }

    // ------------------------------------------------------------------ records

    function registerRecord(bytes32 recordId, bytes32 contentHash) external {
        if (contentHash == bytes32(0)) revert InvalidHash();
        if (_records[recordId].owner != address(0)) revert RecordExists();
        uint64 nowTs = uint64(block.timestamp);
        _records[recordId] = Record(msg.sender, contentHash, nowTs, nowTs, false);
        emit RecordRegistered(recordId, msg.sender);
    }

    function updateRecord(bytes32 recordId, bytes32 newHash) external onlyOwner(recordId) {
        if (newHash == bytes32(0)) revert InvalidHash();
        Record storage r = _records[recordId];
        r.contentHash = newHash;
        r.updatedAt = uint64(block.timestamp);
        emit RecordUpdated(recordId);
    }

    /// @notice Crypto-shredding: the off-chain gateway deletes ciphertext and wrapped keys
    ///         once this flag is set; the digest is cleared from the current state.
    function eraseRecord(bytes32 recordId) external onlyOwner(recordId) {
        Record storage r = _records[recordId];
        r.erased = true;
        r.contentHash = bytes32(0);
        r.updatedAt = uint64(block.timestamp);
        emit RecordErased(recordId);
    }

    // ------------------------------------------------------------------ consent

    function grantAccess(bytes32 recordId, address grantee, uint64 expiresAt) external onlyOwner(recordId) {
        if (!isInstitution[grantee]) revert NotInstitution();
        if (expiresAt <= block.timestamp) revert InvalidExpiry();
        _grants[recordId][grantee] = Grant(expiresAt, false);
        emit AccessGranted(recordId, grantee, expiresAt);
    }

    function revokeAccess(bytes32 recordId, address grantee) external onlyOwner(recordId) {
        _grants[recordId][grantee].revoked = true;
        emit AccessRevoked(recordId, grantee);
    }

    // ------------------------------------------------------------------ queries

    function getRecord(bytes32 recordId)
        external
        view
        returns (address owner, bytes32 contentHash, uint64 createdAt, uint64 updatedAt, bool erased)
    {
        Record storage r = _records[recordId];
        return (r.owner, r.contentHash, r.createdAt, r.updatedAt, r.erased);
    }

    function getGrant(bytes32 recordId, address grantee) external view returns (uint64 expiresAt, bool revoked) {
        Grant storage g = _grants[recordId][grantee];
        return (g.expiresAt, g.revoked);
    }

    function hasAccess(bytes32 recordId, address account) public view returns (bool) {
        Record storage r = _records[recordId];
        if (r.owner == address(0) || r.erased) return false;
        if (account == r.owner) return true;
        if (!isInstitution[account]) return false;
        Grant storage g = _grants[recordId][account];
        return !g.revoked && g.expiresAt >= block.timestamp;
    }

    // ------------------------------------------------------------------ audit

    /// @notice Called by an accessor after retrieving a record; `requestHash` binds the
    ///         entry to the signed off-chain request without revealing its content.
    function logAccess(bytes32 recordId, bytes32 requestHash) external {
        if (!hasAccess(recordId, msg.sender)) revert AccessDenied();
        emit AccessLogged(recordId, msg.sender, requestHash);
    }
}
