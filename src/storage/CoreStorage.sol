// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CoreStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Cluster.Core`.
/// @dev    Slot literal pinned in `docs/specs/cluster-v4-diamond-and-member-uups.md` §19.2.
///         Drift between this constant and the spec table fails CI.
library CoreStorage {
    /// @custom:storage-location erc7201:teesql.storage.Cluster.Core
    struct Layout {
        // Cluster identity
        string clusterId;
        // Cluster-wide governance authority lives in solidstate's
        // OwnableStorage (slot keccak256("solidstate.contracts.storage.Ownable")),
        // wired to the diamond's pre-registered owner() / transferOwnership /
        // acceptOwnership selectors. NOT in this namespace — single source of
        // truth for "who owns this cluster."
        // Member factory pointer (chain singleton; rotatable per Q9)
        address factory;
        // Diamond cumulative cut counter (++ on every diamondCut by AdminFacet)
        uint256 clusterVersion;
        // Membership
        mapping(bytes32 => Member) members;
        mapping(address => bytes32) instanceToMember;
        mapping(address => bytes32) derivedToMember;
        mapping(address => bytes32) passthroughToMember;
        mapping(bytes32 => uint256) memberNonce;
        // Onboarding mailbox
        mapping(bytes32 => OnboardMsg[]) onboarding;
        // Leader registry (no TTL — replaced only by higher-epoch claimLeader)
        bytes32 leaderMemberId;
        uint256 leaderEpoch;
        // Passthrough registry — populated by createMember
        mapping(address => bool) isOurPassthrough;
        // Member sequence counter for default-salt mints
        uint256 nextMemberSeq;
        // Pause authority + flag
        address pauser;
        bool paused;
    }

    struct Member {
        address instanceId;
        bytes derivedPubkey;
        address derivedAddr;
        address passthrough;
        bytes endpoint; // AES-GCM ct of tailnet IP; peer-to-peer only
        uint256 registeredAt;
        bytes publicEndpoint; // UTF-8 customer-facing URL
        string dnsLabel; // per-member DNS UUID
    }

    struct OnboardMsg {
        bytes32 fromMember;
        bytes encryptedPayload;
    }

    bytes32 internal constant SLOT = 0x0d2b39176970d8d514a9c53ecdd18f476e2d8dc24d9a92c32af469b1408bb000;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}
