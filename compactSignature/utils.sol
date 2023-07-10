

function getCompactSignatureValues(bytes memory signature) pure returns (bytes32 r, bytes32 s, uint8 v){
  /// @solidity memory-safe-assembly
  assembly {
    r := mload(add(signature, 0x20))
    let vs := mload(add(signature, 0x40))
    s := and(vs, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    v := sub(28, iszero(shr(255, vs)))
  }
}