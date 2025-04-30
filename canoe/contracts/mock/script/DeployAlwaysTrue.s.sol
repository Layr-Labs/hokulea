// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "../src/AlwaysTrue.sol";

import "forge-std/Script.sol";

contract DeployAlwaysTrue is Script {
    function run() external {
        vm.startBroadcast();

        AlwaysTrue contractInstance = new AlwaysTrue();

        console.log("AlwaysTrue contract deployed at:", address(contractInstance));

        vm.stopBroadcast();
    }
}
