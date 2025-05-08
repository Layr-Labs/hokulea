// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "../src/EigenDACertMockVerifier.sol";

contract AlwaysTrueTest is Test {
    EigenDACertMockVerifier public at;

    function setUp() public {
        at = new EigenDACertMockVerifier();        
    }

    function test_return() public view {
        BatchHeaderV2 memory bh;
        BlobInclusionInfo memory bi;
        NonSignerStakesAndSignature memory nss;
        bytes memory quorums;
        assertEq(at.verifyDACertV2ForZKProof(bh, bi, nss, quorums), true);
    }
}

