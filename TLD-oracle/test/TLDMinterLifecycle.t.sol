// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../contracts/TLDMinter.sol";
import "../contracts/interfaces/ITLDMinter.sol";
import "../contracts/interfaces/IDNSSEC.sol";
import "../contracts/mocks/MockENS.sol";
import "../contracts/mocks/MockRoot.sol";

contract MockSecurityCouncilLC {
    uint256 public expiration;

    constructor(uint256 _expiration) {
        expiration = _expiration;
    }
}

contract MockDNSSECOracleLC {
    bytes public rrData;
    uint32 public inception;

    function setResponse(bytes memory _data, uint32 _inception) external {
        rrData = _data;
        inception = _inception;
    }

    function verifyRRSet(
        IDNSSEC.RRSetWithSignature[] calldata
    ) external view returns (bytes memory, uint32) {
        return (rrData, inception);
    }

    function verifyRRSet(
        IDNSSEC.RRSetWithSignature[] calldata,
        uint256
    ) external view returns (bytes memory, uint32) {
        return (rrData, inception);
    }
}

contract TLDMinterLifecycleTest is Test {
    TLDMinter public minter;
    MockENS public mockEns;
    MockRoot public mockRoot;
    MockDNSSECOracleLC public mockOracle;
    MockSecurityCouncilLC public mockSC;

    address public dao = address(0xDA0);
    address public scMultisig = address(0x5C);
    address public alice = address(0xA11CE);

    uint256 constant TIMELOCK = 15 minutes;

    function setUp() public {
        mockEns = new MockENS();
        mockRoot = new MockRoot(address(mockEns));
        mockOracle = new MockDNSSECOracleLC();
        mockSC = new MockSecurityCouncilLC(block.timestamp + 365 days);

        minter = new TLDMinter(
            address(mockOracle),
            address(mockRoot),
            address(mockEns),
            dao,
            scMultisig,
            address(mockSC),
            TIMELOCK,
            10,          // rateLimitMax
            7 days,      // rateLimitPeriod
            14 days      // proofMaxAge
        );

        mockRoot.setController(address(minter), true);
    }

    // ─────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────

    function _submitClaim(string memory tld) internal returns (bytes32 labelHash) {
        bytes memory name = _dnsWireFormat(tld);
        labelHash = keccak256(bytes(tld));

        // Set oracle response for this specific TLD
        bytes memory rrData = _buildRRData(name, alice);
        mockOracle.setResponse(rrData, uint32(block.timestamp));

        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);
        minter.submitClaim(name, proof);
    }

    function _dnsWireFormat(string memory tld) internal pure returns (bytes memory) {
        bytes memory label = bytes(tld);
        bytes memory result = new bytes(label.length + 2);
        result[0] = bytes1(uint8(label.length));
        for (uint256 i = 0; i < label.length; i++) {
            result[i + 1] = label[i];
        }
        result[label.length + 1] = 0x00;
        return result;
    }

    function _buildRRData(
        bytes memory name,
        address owner
    ) internal pure returns (bytes memory) {
        bytes memory dnsName = abi.encodePacked(hex"045f656e73036e6963", name);
        bytes memory addrHex = _addressToHex(owner);
        bytes memory txtValue = abi.encodePacked("a=0x", addrHex);

        uint16 txtLen = uint16(txtValue.length);
        uint16 rdLength = uint16(txtLen + 1);

        bytes memory rr = abi.encodePacked(
            dnsName,
            uint16(16),    // TYPE_TXT
            uint16(1),     // CLASS_INET
            uint32(3600),  // TTL
            rdLength,
            uint8(txtLen),
            txtValue
        );

        return rr;
    }

    function _addressToHex(address addr) internal pure returns (bytes memory) {
        bytes memory result = new bytes(40);
        bytes16 hexChars = "0123456789abcdef";
        uint160 value = uint160(addr);
        for (uint256 i = 39; i < 40; i--) {
            result[i] = hexChars[value & 0xf];
            value >>= 4;
            if (i == 0) break;
        }
        return result;
    }

    function _allowlistTLD(string memory tld) internal {
        vm.prank(dao);
        minter.addToAllowlist(tld);
    }

    // ─────────────────────────────────────────────────────────────────
    // Happy Path
    // ─────────────────────────────────────────────────────────────────

    function test_submitAndExecute() public {
        _allowlistTLD("link");
        bytes32 labelHash = _submitClaim("link");

        // Warp past timelock
        vm.warp(block.timestamp + TIMELOCK + 1);

        vm.expectEmit(true, true, false, false);
        emit ITLDMinter.TLDMinted(labelHash, alice);
        minter.execute(labelHash);

        // Verify ENS ownership
        bytes32 node = keccak256(abi.encodePacked(bytes32(0), labelHash));
        assertEq(mockEns.owner(node), alice);
    }

    function test_submitEmitsClaimSubmitted() public {
        _allowlistTLD("link");

        bytes memory name = _dnsWireFormat("link");
        bytes32 labelHash = keccak256("link");
        bytes memory rrData = _buildRRData(name, alice);
        uint32 inception = uint32(block.timestamp);
        mockOracle.setResponse(rrData, inception);

        uint256 expectedUnlock = block.timestamp + TIMELOCK;

        vm.expectEmit(true, true, false, true);
        emit ITLDMinter.ClaimSubmitted(labelHash, alice, name, inception, expectedUnlock);

        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);
        minter.submitClaim(name, proof);
    }

    // ─────────────────────────────────────────────────────────────────
    // Veto Path
    // ─────────────────────────────────────────────────────────────────

    function test_daoVeto() public {
        _allowlistTLD("link");
        bytes32 labelHash = _submitClaim("link");

        vm.prank(dao);
        minter.veto(labelHash, "suspicious claim");

        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.ClaimWasVetoed.selector, labelHash));
        minter.execute(labelHash);
    }

    function test_securityCouncilVeto() public {
        _allowlistTLD("link");
        bytes32 labelHash = _submitClaim("link");

        vm.prank(scMultisig);
        minter.veto(labelHash, "emergency veto");

        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.ClaimWasVetoed.selector, labelHash));
        minter.execute(labelHash);
    }

    function test_nonAuthorityCannotVeto() public {
        _allowlistTLD("link");
        bytes32 labelHash = _submitClaim("link");

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.NotVetoAuthority.selector, alice));
        minter.veto(labelHash, "unauthorized");
    }

    // ─────────────────────────────────────────────────────────────────
    // Timelock
    // ─────────────────────────────────────────────────────────────────

    function test_executeBeforeTimelockReverts() public {
        _allowlistTLD("link");
        bytes32 labelHash = _submitClaim("link");

        ITLDMinter.MintRequest memory req = minter.getRequest(labelHash);
        vm.expectRevert(
            abi.encodeWithSelector(TLDMinter.TimelockNotExpired.selector, req.unlockTime, block.timestamp)
        );
        minter.execute(labelHash);
    }

    function test_executeNoPendingReverts() public {
        bytes32 labelHash = keccak256("nonexistent");
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.NoPendingRequest.selector, labelHash));
        minter.execute(labelHash);
    }

    // ─────────────────────────────────────────────────────────────────
    // Duplicate / Existing TLD
    // ─────────────────────────────────────────────────────────────────

    function test_duplicateClaimReverts() public {
        _allowlistTLD("link");
        bytes32 labelHash = _submitClaim("link");

        bytes memory name = _dnsWireFormat("link");
        bytes memory rrData = _buildRRData(name, alice);
        mockOracle.setResponse(rrData, uint32(block.timestamp));

        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.ClaimAlreadyPending.selector, labelHash));
        minter.submitClaim(name, proof);
    }

    function test_tldAlreadyExistsReverts() public {
        _allowlistTLD("link");
        bytes32 labelHash = keccak256("link");

        // Pre-set the TLD owner in ENS
        bytes32 node = keccak256(abi.encodePacked(bytes32(0), labelHash));
        mockEns.setOwner(node, alice);

        bytes memory name = _dnsWireFormat("link");
        bytes memory rrData = _buildRRData(name, alice);
        mockOracle.setResponse(rrData, uint32(block.timestamp));

        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.TLDAlreadyExists.selector, labelHash));
        minter.submitClaim(name, proof);
    }

    // ─────────────────────────────────────────────────────────────────
    // Proof Freshness
    // ─────────────────────────────────────────────────────────────────

    function test_proofTooOldReverts() public {
        // Warp to a realistic timestamp so the subtraction doesn't underflow
        vm.warp(30 days);

        _allowlistTLD("link");

        bytes memory name = _dnsWireFormat("link");
        bytes memory rrData = _buildRRData(name, alice);
        uint32 staleInception = uint32(block.timestamp - 15 days);
        mockOracle.setResponse(rrData, staleInception);

        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.ProofTooOld.selector, staleInception, 14 days));
        minter.submitClaim(name, proof);
    }

    // ─────────────────────────────────────────────────────────────────
    // Rate Limiting
    // ─────────────────────────────────────────────────────────────────

    // 11 unique TLD names for rate limit tests
    string[11] private _rateTLDs = ["aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk"];

    function _allowlistRateTLDs() internal {
        string[] memory tlds = new string[](11);
        for (uint256 i = 0; i < 11; i++) {
            tlds[i] = _rateTLDs[i];
        }
        vm.prank(dao);
        minter.batchAddToAllowlist(tlds);
    }

    function test_rateLimitExceeded() public {
        _allowlistRateTLDs();

        // Submit 10 claims (at the limit)
        for (uint256 i = 0; i < 10; i++) {
            _submitClaim(_rateTLDs[i]);
        }

        // 11th should revert
        bytes memory name = _dnsWireFormat(_rateTLDs[10]);
        bytes memory rrData = _buildRRData(name, alice);
        mockOracle.setResponse(rrData, uint32(block.timestamp));

        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.RateLimitExceeded.selector, 10, 10));
        minter.submitClaim(name, proof);
    }

    function test_rateLimitResets() public {
        _allowlistRateTLDs();

        // Submit 10 claims
        for (uint256 i = 0; i < 10; i++) {
            _submitClaim(_rateTLDs[i]);
        }

        // Warp past rate limit period
        vm.warp(block.timestamp + 7 days + 1);

        // 11th should succeed after period reset
        _submitClaim(_rateTLDs[10]);

        bytes32 labelHash = keccak256(bytes(_rateTLDs[10]));
        ITLDMinter.MintRequest memory req = minter.getRequest(labelHash);
        assertEq(req.owner, alice);
    }

    // ─────────────────────────────────────────────────────────────────
    // Pause
    // ─────────────────────────────────────────────────────────────────

    function test_pauseBlocksSubmit() public {
        _allowlistTLD("link");

        vm.prank(dao);
        minter.pause();

        bytes memory name = _dnsWireFormat("link");
        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);

        vm.expectRevert(TLDMinter.ContractPaused.selector);
        minter.submitClaim(name, proof);
    }

    function test_pauseBlocksExecute() public {
        _allowlistTLD("link");
        bytes32 labelHash = _submitClaim("link");

        // Pause after submit
        vm.prank(dao);
        minter.pause();

        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.expectRevert(TLDMinter.ContractPaused.selector);
        minter.execute(labelHash);
    }

    // ─────────────────────────────────────────────────────────────────
    // Security Council Expiration
    // ─────────────────────────────────────────────────────────────────

    function test_revokeSecurityCouncilVeto() public {
        _allowlistTLD("link");
        bytes32 labelHash = _submitClaim("link");

        // Warp past SC expiration
        vm.warp(block.timestamp + 366 days);

        // Revoke SC veto authority
        minter.revokeSecurityCouncilVeto();
        assertTrue(minter.securityCouncilVetoRevoked());

        // SC can no longer veto
        vm.prank(scMultisig);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.NotVetoAuthority.selector, scMultisig));
        minter.veto(labelHash, "too late");
    }

    function test_revokeBeforeExpirationReverts() public {
        vm.expectRevert(TLDMinter.SecurityCouncilNotExpired.selector);
        minter.revokeSecurityCouncilVeto();
    }
}
