// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "../src/AlwaysTrue.sol";

contract AlwaysTrueTest is Test {
    AlwaysTrue public at;

    function setUp() public {
        at = new AlwaysTrue();        
    }

    function test_return() public view {
        BatchHeaderV2 memory bh;
        BlobInclusionInfo memory bi;
        NonSignerStakesAndSignature memory nss;
        bytes memory quorums;
        assertEq(at.alwaysReturnsTrue(bh, bi, nss, quorums), true);
    }
}

