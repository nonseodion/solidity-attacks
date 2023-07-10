/**
* @dev Util functions for manipulating string and signatures
*/

function getSignatureValues(bytes memory signature) pure returns (bytes32 r, bytes32 s, uint8 v){
  /// @solidity memory-safe-assembly
  assembly {
    r := mload(add(signature, 0x20))
    s := mload(add(signature, 0x40))
    v := shr(248, mload(add(signature, 0x60)))
  }
}

function toEthSignedMessageHash(uint256 amount) pure returns (bytes32 hash){
  uint256 lengthInNumbers = getUint256Length(amount);
  string memory lengthInString = getUint256String(lengthInNumbers, getUint256Length(lengthInNumbers));

  return keccak256(
    abi.encodePacked(
      "\x19Ethereum Signed Message:\n", 
      lengthInString, 
      getUint256String(amount, lengthInNumbers)
    )
  );
}

function getUint256Length(uint256 value) pure returns (uint256 length) {
  if(value == 0) return 0;

  while(true){
    value /= 10;
    length++;
    if(value == 0){
      break;
    }
  }
}

function getUint256String(uint256 value, uint256 length) pure returns (string memory){
  bytes16 symbols = "0123456789";
  string memory stringValue = new string(length);

  /// @solidity memory-safe-assembly
  assembly{
    let index := add(stringValue, add(0x20, sub(length, 1)))
    for {} gt(index, add(stringValue, 0x1f)) {index := sub(index, 1)}{
      mstore8(index, byte(mod(value, 10), symbols))
      value := div(value, 10)
    }
  }

  return stringValue;
}
