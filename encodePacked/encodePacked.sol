// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.4;

import "forge-std/Script.sol";

/** 
* ------------------- abi.encodePacked Vulnerability -------------------
* This test shows keccak256 hash collisions when abi.encodePacked is used.
* The hash collision is caused because of the way abi.encodePacked works.
* It simply concatenates static types like ints and uints with no padding unlike abi.encode.
* For dynamic types like strings and bytes it encodes them in place without their lengths and with no padding unlike abi.encode.
* The missing lengths and lack of padding allow the abi.encodePacked encodeing of 2 different strings to be equal
* E.g abi.encodePacked("ab", "c") == abi.encodePacked("a", "bc");
* Therefore, keccak256(abi.encodePacked("ab", "c")) == keccak256(abi.encodePacked("a", "bc"));
* The contracts below gives a pratical example.
*/

/**
* ------------------- Contract Vulnerability -------------------
* The FarmRegistry contract below stores a register of animals owned by a farmer at a particular time.
* A hash of the output of ebi.encodePacked is used as a key and leads to a collision which causes an overwrite of data.
* The use of abi.encodePacked was the cause of the collision.
*/

/**
* ------------------- Mitigation -------------------
* In FarmRegistry abi.encodePacked is used because keccak256 expects a bytes memory input.
* For this context, abi.encode can be used instead to prevent collision. It pads types properly and adds a length to dynamic types.
*/

contract Hacker is Script {
    function setUp() public {}

    function run() public {
        FarmRegistry registry = new FarmRegistry();

        bytes32 key1 = registry.registerOne("bulldog");

        string memory key1Animal = registry.register(key1, 0);
        console.log(key1Animal); // bulldog

        bytes32 key2 = registry.registerTwo("bull", "dog");
        string memory key2Animal = registry.register(key2, 0);
        console.log(key2Animal); // bull

        console.logBytes32(key1); // 0xd432ef3fccd23b6b29f2045f1b9ae02cca9913ab6d1f69a78181d5e93e8a1046
        console.logBytes32(key2); // 0xd432ef3fccd23b6b29f2045f1b9ae02cca9913ab6d1f69a78181d5e93e8a1046


        key1Animal = registry.register(key1, 0);
        console.log(key1Animal); // bull
    }
}


contract FarmRegistry {
    mapping(bytes32 => string[]) public register;
    address farmer = msg.sender;

    modifier onlyFarmer() {
        require(msg.sender == farmer);
        _;
    }

    function registerOne(string calldata animal) external returns (bytes32) {
        bytes32 key = keccak256(
            abi.encodePacked(farmer, animal, block.timestamp)
        );

        register[key] = [animal];
        return key;
    }

    function registerTwo(
        string calldata animal1,
        string calldata animal2
    ) external returns (bytes32) {
        bytes32 key = keccak256(
            abi.encodePacked(farmer, animal1, animal2, block.timestamp)
        );
        register[key] = [animal1, animal2];
        return key;
    }
}
