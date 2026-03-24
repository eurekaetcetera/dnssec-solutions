// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../contracts/TLDMinter.sol";
import "../contracts/interfaces/ITLDMinter.sol";
import "../contracts/interfaces/IDNSSEC.sol";
import "../contracts/mocks/MockENS.sol";
import "../contracts/mocks/MockRoot.sol";

contract MockSecurityCouncil {
    uint256 public expiration;

    constructor(uint256 _expiration) {
        expiration = _expiration;
    }
}

contract MockDNSSECOracle {
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

contract TLDMinterAllowlistTest is Test {
    TLDMinter public minter;
    MockENS public mockEns;
    MockRoot public mockRoot;
    MockDNSSECOracle public mockOracle;
    MockSecurityCouncil public mockSC;

    address public dao = address(0xDA0);
    address public scMultisig = address(0x5C);
    address public alice = address(0xA11CE);

    function setUp() public {
        mockEns = new MockENS();
        mockRoot = new MockRoot(address(mockEns));
        mockOracle = new MockDNSSECOracle();
        mockSC = new MockSecurityCouncil(block.timestamp + 365 days);

        string[] memory emptyList = new string[](0);
        minter = new TLDMinter(
            address(mockOracle),
            address(mockRoot),
            address(mockEns),
            dao,
            scMultisig,
            address(mockSC),
            15 minutes,  // timelockDuration
            10,          // rateLimitMax
            7 days,      // rateLimitPeriod
            14 days,     // proofMaxAge
            emptyList
        );

        // Give minter controller access on root
        mockRoot.setController(address(minter), true);
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 1: Claim rejected for non-allowlisted TLD
    // ─────────────────────────────────────────────────────────────────

    function test_rejectNonAllowlistedTLD() public {
        // "link" in DNS wire format: 0x046c696e6b00
        bytes memory name = hex"046c696e6b00";
        bytes32 labelHash = keccak256("link");

        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);

        vm.expectRevert(abi.encodeWithSelector(TLDMinter.TLDNotAllowed.selector, labelHash));
        minter.submitClaim(name, proof);
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 2: Claim accepted for allowlisted TLD
    // ─────────────────────────────────────────────────────────────────

    function test_acceptAllowlistedTLD() public {
        // Add "link" to allowlist
        vm.prank(dao);
        minter.addToAllowlist("link");

        // Build mock oracle response with valid TXT record
        // _ens.nic.link TXT "a=0x<alice address>"
        bytes memory name = hex"046c696e6b00";
        bytes memory rrData = _buildRRData(name, alice);
        mockOracle.setResponse(rrData, uint32(block.timestamp));

        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);
        minter.submitClaim(name, proof);

        // Verify request was stored
        bytes32 labelHash = keccak256("link");
        ITLDMinter.MintRequest memory req = minter.getRequest(labelHash);
        assertEq(req.owner, alice);
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 3: DAO-only enforcement on addToAllowlist
    // ─────────────────────────────────────────────────────────────────

    function test_onlyDAOCanAdd() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.NotDAO.selector, alice));
        minter.addToAllowlist("link");
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 4: DAO-only enforcement on removeFromAllowlist
    // ─────────────────────────────────────────────────────────────────

    function test_onlyDAOCanRemove() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.NotDAO.selector, alice));
        minter.removeFromAllowlist("link");
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 5: Batch add
    // ─────────────────────────────────────────────────────────────────

    function test_batchAdd() public {
        string[] memory tlds = new string[](3);
        tlds[0] = "link";
        tlds[1] = "click";
        tlds[2] = "help";

        vm.prank(dao);
        minter.batchAddToAllowlist(tlds);

        assertTrue(minter.allowedTLDs(keccak256(abi.encodePacked("link"))));
        assertTrue(minter.allowedTLDs(keccak256(abi.encodePacked("click"))));
        assertTrue(minter.allowedTLDs(keccak256(abi.encodePacked("help"))));
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 6: Remove from allowlist then claim rejected
    // ─────────────────────────────────────────────────────────────────

    function test_removeThenReject() public {
        // Add then remove
        vm.startPrank(dao);
        minter.addToAllowlist("link");
        minter.removeFromAllowlist("link");
        vm.stopPrank();

        assertFalse(minter.allowedTLDs(keccak256(abi.encodePacked("link"))));

        // Try to claim — should revert
        bytes memory name = hex"046c696e6b00";
        bytes32 labelHash = keccak256("link");
        IDNSSEC.RRSetWithSignature[] memory proof = new IDNSSEC.RRSetWithSignature[](0);

        vm.expectRevert(abi.encodeWithSelector(TLDMinter.TLDNotAllowed.selector, labelHash));
        minter.submitClaim(name, proof);
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 7: Constructor seeds allowlist
    // ─────────────────────────────────────────────────────────────────

    function test_constructorSeedsAllowlist() public {
        string[] memory initialList = new string[](3);
        initialList[0] = "link";
        initialList[1] = "click";
        initialList[2] = "help";

        TLDMinter seeded = new TLDMinter(
            address(mockOracle),
            address(mockRoot),
            address(mockEns),
            dao,
            scMultisig,
            address(mockSC),
            15 minutes,
            10,
            7 days,
            14 days,
            initialList
        );

        assertTrue(seeded.allowedTLDs(keccak256(abi.encodePacked("link"))));
        assertTrue(seeded.allowedTLDs(keccak256(abi.encodePacked("click"))));
        assertTrue(seeded.allowedTLDs(keccak256(abi.encodePacked("help"))));
        assertFalse(seeded.allowedTLDs(keccak256(abi.encodePacked("com"))));
    }

    // ─────────────────────────────────────────────────────────────────
    // Helper: Build mock RR data with TXT record
    // ─────────────────────────────────────────────────────────────────

    function _buildRRData(
        bytes memory name,
        address owner
    ) internal pure returns (bytes memory) {
        // Construct the DNS name: _ens.nic.<tld>
        // \x04_ens\x03nic + name
        bytes memory dnsName = abi.encodePacked(hex"045f656e73036e6963", name);

        // Build the TXT record value: "a=0x" + hex address
        bytes memory addrHex = _addressToHex(owner);
        bytes memory txtValue = abi.encodePacked("a=0x", addrHex);

        // RR format: name + type(2) + class(2) + ttl(4) + rdlength(2) + rdata
        // rdata for TXT: length-prefixed string
        uint16 txtLen = uint16(txtValue.length);
        uint16 rdLength = uint16(txtLen + 1); // 1 byte for string length prefix

        bytes memory rr = abi.encodePacked(
            dnsName,           // DNS name
            uint16(16),        // TYPE_TXT
            uint16(1),         // CLASS_INET
            uint32(3600),      // TTL
            rdLength,          // RDLENGTH
            uint8(txtLen),     // TXT string length
            txtValue           // TXT string data
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
}
