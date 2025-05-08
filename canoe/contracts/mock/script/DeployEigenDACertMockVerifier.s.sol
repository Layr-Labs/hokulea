// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "../src/EigenDACertMockVerifier.sol";

import "forge-std/Script.sol";

contract DeployEigenDACertMockVerifier is Script {
    function run() external {
        vm.startBroadcast();

        EigenDACertMockVerifier contractInstance = new EigenDACertMockVerifier();

        console.log("AlwaysTrue contract deployed at:", address(contractInstance));

        vm.stopBroadcast();
    }
}
