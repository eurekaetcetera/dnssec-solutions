// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "./DnssecP256Verifier.sol";
import "./interfaces/IExtendedResolver.sol";
import {IERC165} from "../lib/forge-std/src/interfaces/IERC165.sol";

/// @notice Minimal ENS registry interface needed for resolution routing.
interface IENSRegistry {
    function resolver(bytes32 node) external view returns (address);
    function owner(bytes32 node) external view returns (address);
}

/// @notice NameWrapper interface for wrapped name support
interface INameWrapper {
    function ownerOf(uint256 id) external view returns (address);
}

/// @dev EIP-3668 CCIP-Read error.
error OffchainLookup(
    address sender,
    string[] urls,
    bytes callData,
    bytes4 callbackFunction,
    bytes extraData
);

error NotImplemented(string context);
error InvalidAddress(string field);
error Unauthorized();
error VerificationFailed();
error MissingDnsLink();
error TxtRecordNotFound();
error InvalidTxtFormat();
error ResolverNotSet();
error ResolverCallFailed();
error BidirectionalLinkMismatch();
error UnrecognizedRevert();
error TargetResolverNotSet();
error UnsupportedSelector();
error NotNodeOwner(bytes32 node);

/// @title DnssecResolver
/// @notice Resolver scaffold for DNSSEC-backed ENS resolution (Algorithm 13).
/// @dev Sprint 1: structure, interfaces, imports only. Resolution logic to follow.
contract DnssecResolver is IExtendedResolver, IERC165 {
    IDnssecP256Verifier public verifier;
    IENSRegistry public ensRegistry;
    string public gatewayUrl;
    address public owner;

    /// @notice Optional mapping to enforce bidirectional DNS ↔ ENS linking.
    mapping(bytes32 => bytes) public dnsNameByEnsNode;

    /// @notice Simple onchain storage for records (Option B: direct storage, no delegation).
    mapping(bytes32 => address) private addrRecords;
    mapping(bytes32 => mapping(uint256 => bytes)) private addressRecords; // Multi-coin address support
    mapping(bytes32 => mapping(string => string)) private textRecords;

    /// @notice Operator approvals: (owner, operator) => approved
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    
    /// @notice Delegate approvals: (owner, node, delegate) => approved
    mapping(address => mapping(bytes32 => mapping(address => bool))) private _delegateApprovals;
    
    /// @notice Record versions for IVersionableResolver compatibility
    mapping(bytes32 => uint64) public recordVersions;

    event VerifierUpdated(address indexed verifier);
    event EnsRegistryUpdated(address indexed registry);
    event GatewayUrlUpdated(string gatewayUrl);
    event DnsNameLinked(bytes32 indexed node, bytes dnsNameWire);
    event AddrChanged(bytes32 indexed node, address addr);
    event AddressChanged(bytes32 indexed node, uint256 indexed coinType, bytes newAddress);
    event TextChanged(bytes32 indexed node, string indexed indexedKey, string key, string value);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event Approved(address indexed owner, bytes32 indexed node, address indexed delegate, bool approved);
    event VersionChanged(bytes32 indexed node, uint64 newVersion);

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyNodeOwner(bytes32 node) {
        address nodeOwner = ensRegistry.owner(node);
        
        // Handle wrapped names: if owner is NameWrapper, get the actual owner from NameWrapper
        // Sepolia NameWrapper address (standard deployment)
        address nameWrapper = 0x0635513f179D50A207757E05759CbD106d7dFcE8;
        if (nodeOwner == nameWrapper) {
            INameWrapper wrapper = INameWrapper(nameWrapper);
            nodeOwner = wrapper.ownerOf(uint256(node));
        }
        
        // Check if sender is owner, or has operator approval, or has delegate approval
        bool isAuthorized = 
            nodeOwner == msg.sender ||
            _operatorApprovals[nodeOwner][msg.sender] ||
            _delegateApprovals[nodeOwner][node][msg.sender];
        
        if (!isAuthorized) revert NotNodeOwner(node);
        _;
    }

    constructor(
        IDnssecP256Verifier verifier_,
        IENSRegistry ensRegistry_,
        string memory gatewayUrl_
    ) {
        if (address(verifier_) == address(0)) revert InvalidAddress("verifier");
        if (address(ensRegistry_) == address(0)) revert InvalidAddress("ensRegistry");
        verifier = verifier_;
        ensRegistry = ensRegistry_;
        gatewayUrl = gatewayUrl_;
        owner = msg.sender;

        emit VerifierUpdated(address(verifier_));
        emit EnsRegistryUpdated(address(ensRegistry_));
        emit GatewayUrlUpdated(gatewayUrl_);
    }

    // =============================================================
    // Admin
    // =============================================================

    function setVerifier(IDnssecP256Verifier verifier_) external onlyOwner {
        if (address(verifier_) == address(0)) revert InvalidAddress("verifier");
        verifier = verifier_;
        emit VerifierUpdated(address(verifier_));
    }

    function setEnsRegistry(IENSRegistry ensRegistry_) external onlyOwner {
        if (address(ensRegistry_) == address(0)) revert InvalidAddress("ensRegistry");
        ensRegistry = ensRegistry_;
        emit EnsRegistryUpdated(address(ensRegistry_));
    }

    function setGatewayUrl(string calldata gatewayUrl_) external onlyOwner {
        gatewayUrl = gatewayUrl_;
        emit GatewayUrlUpdated(gatewayUrl_);
    }

    function linkDnsName(bytes32 node, bytes calldata dnsNameWire) external onlyOwner {
        dnsNameByEnsNode[node] = dnsNameWire;
        emit DnsNameLinked(node, dnsNameWire);
    }

    // =============================================================
    // ENSIP-165 support
    // =============================================================

    function supportsInterface(bytes4 interfaceId) public pure override returns (bool) {
        return
            interfaceId == type(IExtendedResolver).interfaceId ||
            interfaceId == type(IERC165).interfaceId ||
            interfaceId == 0x59d1d43c || // text(bytes32,string)
            interfaceId == 0x3b3b57de || // addr(bytes32)
            interfaceId == 0xac9650d8 || // multicall(bytes[]) - for ENS app UI compatibility
            interfaceId == 0xd700ff33 || // IVersionableResolver - recordVersions(bytes32)
            interfaceId == 0xf1cb7e06 || // addr(bytes32,uint) - multi-coin address support
            interfaceId == 0xbc1c58d1 || // contenthash(bytes32)
            interfaceId == 0x2203ab56;  // ABI(bytes32,uint256)
    }
    
    /// @notice Clear all records for a node (IVersionableResolver compatibility)
    /// @dev Increments record version to invalidate cached records
    function clearRecords(bytes32 node) external onlyNodeOwner(node) {
        recordVersions[node]++;
        emit VersionChanged(node, recordVersions[node]);
    }

    // =============================================================
    // Stub implementations for ENS app compatibility
    // =============================================================

    /// @notice Multi-coin address support
    /// @dev Required for ENS app UI compatibility
    function addr(bytes32 node, uint coinType) external view returns (bytes memory) {
        return addressRecords[node][coinType];
    }

    /// @notice Content hash support (stub - returns empty)
    /// @dev Required for ENS app UI compatibility
    function contenthash(bytes32) external pure returns (bytes memory) {
        return "";
    }

    /// @notice ABI support (stub - returns empty)
    /// @dev Required for ENS app UI compatibility
    function ABI(bytes32, uint256) external pure returns (uint256, bytes memory) {
        return (0, "");
    }

    // =============================================================
    // ENSIP-10: resolve
    // =============================================================

    uint16 internal constant QTYPE_TXT = 16;
    bytes4 internal constant ADDR_SELECTOR = bytes4(keccak256("addr(bytes32)"));
    bytes4 internal constant TEXT_SELECTOR = bytes4(keccak256("text(bytes32,string)"));

    function resolve(bytes calldata name, bytes calldata data)
        external
        view
        override
        returns (bytes memory)
    {
        // Convert DNS-encoded ENS name to node, then look up linked DNS name
        bytes32 ensNode = _namehashFromDns(name);
        bytes memory dnsNameWire = dnsNameByEnsNode[ensNode];
        if (dnsNameWire.length == 0) revert MissingDnsLink();

        // Use the linked DNS name for CCIP-Read (not the ENS name)
        bytes memory callData = abi.encode(dnsNameWire, QTYPE_TXT);

        // Pass original context to callback
        bytes memory extraData = abi.encode(dnsNameWire, data, QTYPE_TXT);

        string[] memory urls = new string[](1);
        urls[0] = gatewayUrl;

        revert OffchainLookup(
            address(this),
            urls,
            callData,
            this.ccipCallback.selector,
            extraData
        );
    }

    // =============================================================
    // CCIP-Read callback
    // =============================================================

    function ccipCallback(bytes calldata response, bytes calldata extraData)
        external
        returns (bytes memory)
    {
        // Decode gateway response: proof bundle and question used for verification.
        (bytes memory proofBundle, bytes memory question) = abi.decode(response, (bytes, bytes));

        // Decode original request context; only `data` is needed to route reads.
        bytes memory data;
        {
            bytes memory ignoredName;
            uint16 ignoredQtype;
            (ignoredName, data, ignoredQtype) = abi.decode(extraData, (bytes, bytes, uint16));
        }

        // Extract original query node from callData first
        bytes4 selector;
        assembly {
            selector := mload(add(data, 0x20))
        }

        // Extract data after selector (skip first 4 bytes)
        bytes memory callData;
        assembly {
            let dataLength := mload(data)
            let newLength := sub(dataLength, 4)
            callData := mload(0x40)
            mstore(callData, newLength)
            mstore(0x40, add(callData, add(0x20, newLength)))
            let src := add(data, 0x24) // Skip length (0x20) + selector (0x04)
            let dst := add(callData, 0x20)
            for { let i := 0 } lt(i, newLength) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }

        // Get the original queried node
        bytes32 queriedNode;
        if (selector == ADDR_SELECTOR) {
            (queriedNode) = abi.decode(callData, (bytes32));
        } else if (selector == TEXT_SELECTOR) {
            (queriedNode,) = abi.decode(callData, (bytes32, string));
        } else {
            revert UnsupportedSelector();
        }

        // Verify the DNS name is linked to the queried node
        bytes memory linkedDns = dnsNameByEnsNode[queriedNode];
        if (linkedDns.length == 0) revert MissingDnsLink();

        // Verify the DNS proof is for the linked DNS name
        (bytes memory qnameWire,,) = abi.decode(question, (bytes, uint16, uint16));
        if (keccak256(linkedDns) != keccak256(qnameWire)) {
            revert BidirectionalLinkMismatch();
        }

        // Verify the DNSSEC proof
        (bool ok,) = verifier.verify(proofBundle, question);
        if (!ok) revert VerificationFailed();

        // Return onchain storage for the original queried node
        if (selector == ADDR_SELECTOR) {
            return abi.encode(addrRecords[queriedNode]);
        } else if (selector == TEXT_SELECTOR) {
            (, string memory key) = abi.decode(callData, (bytes32, string));
            // Return onchain storage (empty string if not found, which is correct)
            return abi.encode(textRecords[queriedNode][key]);
        }

        revert UnsupportedSelector();
    }

    // =============================================================
    // ENSIP-5/18: text records (read)
    // =============================================================

    function text(bytes32 node, string calldata key) external view returns (string memory) {
        // First, check if record exists in onchain storage
        string memory storedValue = textRecords[node][key];
        if (bytes(storedValue).length > 0) {
            return storedValue;
        }

        // If not found onchain, fall back to DNS verification
        bytes memory dnsNameWire = dnsNameByEnsNode[node];
        if (dnsNameWire.length == 0) revert MissingDnsLink();

        bytes memory data = abi.encodeWithSelector(TEXT_SELECTOR, node, key);
        _offchainLookup(dnsNameWire, data);
        // Unreachable: _offchainLookup always reverts with OffchainLookup
    }

    // =============================================================
    // ENSIP-137 addr (read)
    // =============================================================

    function addr(bytes32 node) external view returns (address) {
        // First, check if record exists in onchain storage
        address storedAddr = addrRecords[node];
        if (storedAddr != address(0)) {
            return storedAddr;
        }

        // If not found onchain, fall back to DNS verification
        bytes memory dnsNameWire = dnsNameByEnsNode[node];
        if (dnsNameWire.length == 0) revert MissingDnsLink();

        bytes memory data = abi.encodeWithSelector(ADDR_SELECTOR, node);
        _offchainLookup(dnsNameWire, data);
        // Unreachable: _offchainLookup always reverts with OffchainLookup
    }

    // =============================================================
    // Write operations (direct storage)
    // =============================================================

    function setAddr(bytes32 node, address addr_) external onlyNodeOwner(node) {
        uint256 COIN_TYPE_ETH = 60;
        addrRecords[node] = addr_;
        addressRecords[node][COIN_TYPE_ETH] = abi.encodePacked(addr_);
        emit AddrChanged(node, addr_);
        emit AddressChanged(node, COIN_TYPE_ETH, abi.encodePacked(addr_));
    }

    /// @notice Set multi-coin address (for ENS app compatibility)
    function setAddr(bytes32 node, uint256 coinType, bytes calldata a) external onlyNodeOwner(node) {
        addressRecords[node][coinType] = a;
        emit AddressChanged(node, coinType, a);
        // Also emit AddrChanged for ETH (coinType 60) for backwards compatibility
        if (coinType == 60 && a.length == 20) {
            // Convert bytes to address: copy to memory first
            bytes memory addrBytes = a;
            address addr_;
            assembly {
                addr_ := mload(add(addrBytes, 32))
            }
            addrRecords[node] = addr_;
            emit AddrChanged(node, addr_);
        }
    }

    function setText(bytes32 node, string calldata key, string calldata value) external onlyNodeOwner(node) {
        textRecords[node][key] = value;
        emit TextChanged(node, key, key, value);
    }

    // =============================================================
    // Authorization functions (for ENS app UI compatibility)
    // =============================================================

    /// @notice Check if an operator is approved for all nodes by an account
    /// @dev For ENS app compatibility - checks stored approvals
    /// @dev For NameWrapper accounts, returns false (use isApprovedFor with node instead)
    function isApprovedForAll(address account, address operator) external view returns (bool) {
        // Self-approval is always allowed
        if (account == operator) return true;
        
        // If account is NameWrapper, we can't verify ownership without node context
        // Return false - the app should check isApprovedFor(node) instead
        address nameWrapper = 0x0635513f179D50A207757E05759CbD106d7dFcE8;
        if (account == nameWrapper) {
            return false;
        }
        
        // Check stored operator approvals
        return _operatorApprovals[account][operator];
    }

    /// @notice Approve an operator for all nodes (for ENS app compatibility)
    /// @dev Stores operator approvals for ENS app compatibility
    function setApprovalForAll(address operator, bool approved) external {
        require(msg.sender != operator, "Setting approval status for self");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    /// @notice Approve a delegate for a specific node
    /// @dev For ENS app compatibility
    function approve(bytes32 node, address delegate, bool approved) external {
        require(msg.sender != delegate, "Setting delegate status for self");
        _delegateApprovals[msg.sender][node][delegate] = approved;
        emit Approved(msg.sender, node, delegate, approved);
    }

    /// @notice Check if a delegate is approved for a specific node
    /// @dev For ENS app compatibility - checks stored approvals and owner status
    /// @param account The owner address (may be from registry or NameWrapper)
    /// @param node The ENS node to check
    /// @param delegate The address to check approval for
    /// @return true if delegate is approved
    function isApprovedFor(address account, bytes32 node, address delegate) external view returns (bool) {
        // Get actual node owner from registry
        address nodeOwner = ensRegistry.owner(node);
        
        // Handle wrapped names
        address nameWrapper = 0x0635513f179D50A207757E05759CbD106d7dFcE8;
        address actualOwner = nodeOwner;
        if (nodeOwner == nameWrapper) {
            INameWrapper wrapper = INameWrapper(nameWrapper);
            actualOwner = wrapper.ownerOf(uint256(node));
        }
        
        // Delegate is approved if they are the actual node owner
        if (delegate == actualOwner) return true;
        
        // Check stored delegate approvals
        // Try both the account parameter and the actual owner
        return _delegateApprovals[account][node][delegate] || 
               _delegateApprovals[actualOwner][node][delegate];
    }

    // =============================================================
    // Multicall support (for ENS app UI compatibility)
    // =============================================================

    /// @notice Multicall function for batch operations (ENS app UI compatibility)
    /// @dev Simple implementation that processes calls sequentially
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            require(success, "Multicall: call failed");
            results[i] = result;
        }
        return results;
    }

    // =============================================================
    // Internal helpers
    // =============================================================

    /// @dev Parse a TXT RRset and extract the ENS name from a field "ens_name=<name>".
    function _parseEnsNameFromTxt(bytes memory canonicalRrset) internal pure returns (string memory) {
        bytes memory needle = bytes("ens_name=");
        uint256 n = canonicalRrset.length;
        for (uint256 i = 0; i + needle.length < n; i++) {
            bool matchFound = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (canonicalRrset[i + j] != needle[j]) {
                    matchFound = false;
                    break;
                }
            }
            if (matchFound) {
                // Collect characters until end or null/quote
                uint256 start = i + needle.length;
                uint256 end = start;
                while (end < n) {
                    bytes1 c = canonicalRrset[end];
                    if (c == 0x00 || c == 0x22) break; // stop at null or quote
                    end++;
                }
                if (end == start) revert InvalidTxtFormat();
                bytes memory ensNameBytes = new bytes(end - start);
                for (uint256 k = 0; k < ensNameBytes.length; k++) {
                    ensNameBytes[k] = canonicalRrset[start + k];
                }
                return string(ensNameBytes);
            }
        }
        revert TxtRecordNotFound();
    }

    /// @dev Emit OffchainLookup for a given qname/qtype using provided resolver calldata.
    function _offchainLookup(bytes memory qnameWire, bytes memory data) internal view returns (bytes memory) {
        string[] memory urls = new string[](1);
        urls[0] = gatewayUrl;

        revert OffchainLookup(
            address(this),
            urls,
            abi.encode(qnameWire, QTYPE_TXT),
            this.ccipCallback.selector,
            abi.encode(qnameWire, data, QTYPE_TXT)
        );
    }

    /// @dev Namehash a DNS-encoded name (e.g., from resolve() function).
    /// @param dnsName DNS-encoded name (e.g., "\x06dnssec\x03eth\x00")
    /// @return node The namehash of the decoded name
    function _namehashFromDns(bytes memory dnsName) internal pure returns (bytes32) {
        bytes32 node = bytes32(0);
        uint256 offset = 0;
        uint256 len = dnsName.length;
        
        // Decode DNS wire format and compute namehash
        while (offset < len && dnsName[offset] != 0x00) {
            uint8 labelLen = uint8(dnsName[offset]);
            offset++;
            
            if (labelLen == 0) break;
            if (offset + labelLen > len) break;
            
            // Extract label
            bytes memory label = new bytes(labelLen);
            for (uint256 i = 0; i < labelLen; i++) {
                label[i] = dnsName[offset + i];
            }
            offset += labelLen;
            
            // Compute label hash and update node
            bytes32 labelHash = keccak256(label);
            node = keccak256(abi.encodePacked(node, labelHash));
        }
        
        return node;
    }

    /// @dev ENS namehash per EIP-137.
    function _namehash(string memory name) internal pure returns (bytes32) {
        bytes memory s = bytes(name);
        bytes32 node;
        uint256 labelEnd = s.length;
        for (uint256 i = s.length; i > 0; i--) {
            if (s[i - 1] == ".") {
                uint256 labelStart = i;
                uint256 labelLen = labelEnd > labelStart ? labelEnd - labelStart : 0;
                bytes32 labelHash;
                assembly {
                    labelHash := keccak256(add(add(s, 0x20), labelStart), labelLen)
                }
                node = keccak256(abi.encodePacked(node, labelHash));
                labelEnd = i - 1;
            }
        }
        if (labelEnd > 0) {
            bytes32 labelHash;
            assembly {
                labelHash := keccak256(add(add(s, 0x20), 0), labelEnd)
            }
            node = keccak256(abi.encodePacked(node, labelHash));
        }
        return node;
    }

    /// @dev Bubble OffchainLookup revert data from downstream resolvers to support ENSIP-22 recursion.
    function _bubbleOffchainLookup(bytes memory revertData) internal pure {
        if (revertData.length < 4) revert UnrecognizedRevert();
        bytes4 selector;
        assembly {
            selector := mload(add(revertData, 0x20))
        }
        if (selector == OffchainLookup.selector) {
            assembly {
                revert(add(revertData, 0x20), mload(revertData))
            }
        }
    }
}
