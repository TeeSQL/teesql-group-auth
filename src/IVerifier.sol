// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IVerifier
/// @notice Interface every TEE-platform verifier implements so TEEBridge can be platform-agnostic.
/// Based on sxysun's IVerifier.sol from github.com/Account-Link/tee-interop.
interface IVerifier {
    /// @notice Pure verification — no state changes. Use for off-chain checks or view-compatible verifiers.
    function verify(bytes calldata proof)
        external
        view
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData);

    /// @notice Verification with optional caching (e.g. Nitro cert chain). Defaults to calling verify().
    function verifyAndCache(bytes calldata proof)
        external
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData);
}
