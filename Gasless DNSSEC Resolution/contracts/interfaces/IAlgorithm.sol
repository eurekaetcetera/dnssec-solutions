// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IAlgorithm {
    function verify(
        bytes calldata key,
        bytes calldata data,
        bytes calldata signature
    ) external view returns (bool);
}

