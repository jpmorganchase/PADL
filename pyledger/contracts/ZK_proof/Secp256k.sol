pragma solidity ^0.8.20;

import "./EllipticCurve.sol";


uint256   constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
uint256   constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
uint256   constant AA = 0;
uint256   constant BB = 7;
uint256   constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
uint256   constant g = 0xe4c9192893d7a85eb9793f8748e258e1184448f8092bcdd8b77c9403b65495ce;
uint8   constant preg = 0x2;



/// @title A range of operations on elliptic curve and verifies the address using the ecrecover function.
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.
contract Secp256k {

/// @dev function to perform scalar multiplication on an elliptic curve point and verifies the result using the ecrecover function.
/// @dev It returns a boolean indicating whether the verification was successful, along with the coordinates of the resulting point.
/// @param scalar is the  scalar value to multiply.
/// @param x1 is the x-coordinate of the point to multiply.
/// @param y1 is the y-coordinate of the point to multiply.
/// @param wx is the x-coordinate of the resulting popint.
/// @param wy is the y-coordinate of the resulting popint.
function scalMulR(uint256 scalar, uint256 x1, uint256 y1, uint256 wx, uint256 wy) public pure returns (bool, uint256, uint256){
        uint256 order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; //Group order
        address signer = ecrecover(0, y1 % 2 != 0 ? 28 : 27, bytes32(x1), bytes32(mulmod(scalar, x1, order)));
        address xyAddress = address(uint160(uint256(keccak256(abi.encodePacked(wx, wy))) ) );
        return (xyAddress==signer, wx, wy);
    }

/// @dev function to return the result of the SHA-256 hash of the input data and returns a bytes32 value.
/// @param data is the input (message) of arbitrary length to the hash function.
function hashsha256(bytes memory data) public pure returns (bytes32){
    return sha256(data);
}

/// @dev function to  return the result of getting the reault of modular exponentiation, val^e % _PP, where PP is a predefined number.
/// @param val is the base
/// @param e is the exponent
function expMod2(uint256 val, uint256 e) pure public returns (uint256)
{
    return EllipticCurve.expMod(val,e,PP);
}


/// @dev function to return the result of geting the result of (val * e) % PP,  where the multiplication is performed with arbitrary precision and does not wrap around at 2**256.
/// @param val is the number
/// @param e  is another another
function mulMod2(uint256 val, uint256 e) pure public returns (uint256)
{
    return mulmod(val,e, PP);
}


/// @dev function to  return the result of getting the reault of modular exponentiation, val^e % _p./
/// Source: https://asecuritysite.com/ecc/ethereum16
/// @param val is the base
/// @param e is the exponent
/// @param p is the modulus
function expMod(uint256 val, uint256 e, uint256 p) pure public returns (uint256)
{
    return EllipticCurve.expMod(val,e,p);
}

/// @dev function to  return the result of getting the result of modular euclidean inverse of a number (mod p) on Elliptic Curve.
/// @param  val is the number
/// @param  p is the modulus
function invMod(uint256 val, uint256 p) pure public returns (uint256)
{
    return EllipticCurve.invMod(val,p);
}


/// @dev function to return the result of deriving the y-coordinate from a compressed-format point given the x-coordinate.
/// @param prefix parity byte (0x02 even, 0x03 odd)
/// @param x coordinate x
function getY(uint8 prefix, uint256 x) pure public returns (uint256)
{
    return EllipticCurve.deriveY(prefix,x,AA,BB,PP);
}

/// @dev function to  return the result of whether point (x,y) is on curve defined by a, b, and _pp.
/// @param x coordinate x of P1
/// @param y coordinate y of P1
function onCurve(uint256 x, uint256 y) pure public returns (bool)
{
    return EllipticCurve.isOnCurve(x,y,AA,BB,PP);
}

/// @dev function to return the result of calculating inverse (x, -y) of point (x, y).
/// @param x coordinate x of P1
/// @param y coordinate y of P1
function inverse(uint256 x, uint256 y) pure public returns (uint256,
uint256) {
    return EllipticCurve.ecInv(x,y,PP);
  }

/// @dev function to return the result of substracting two points (x1, y1) and (x2, y2) in affine coordinates.
/// @param x1 coordinate x of P1
/// @param y1 coordinate y of P1
/// @param x2 coordinate x of P2
/// @param y2 coordinate y of P2
function subtract(uint256 x1, uint256 y1,uint256 x2, uint256 y2 ) pure public returns (uint256, uint256) {
    return EllipticCurve.ecSub(x1,y1,x2,y2,AA,PP);
  }

/// @dev function to return the result of adding two points (x1, y1) and (x2, y2) in affine coordinates.
/// @param x1 coordinate x of P1
/// @param y1 coordinate y of P1
/// @param x2 coordinate x of P2
/// @param y2 coordinate y of P2
function add(uint256 x1, uint256 y1,uint256 x2, uint256 y2 ) pure public returns (uint256, uint256) {
    return EllipticCurve.ecAdd(x1,y1,x2,y2,AA,PP);
  }


/// @dev function to return the result of multipling point (x1, y1, z1) times d in affine coordinates.
/// @param k scalar to multiply
/// @param x coordinate x of P1
/// @param y coordinate y of P1
function scalMul(uint256 k, uint256 x, uint256 y) public pure returns(uint256, uint256){
    return EllipticCurve.ecMul(k, x, y, AA, PP);
  }


}