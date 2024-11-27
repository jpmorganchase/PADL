// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./bn254.sol";

struct Rangeproof{
    BN254Point A;
    BN254Point S;
    BN254Point T1;
    BN254Point T2;
    uint256 tau_x;
    uint256 miu;
    uint256 tx;
    uint256 a_tag;
    uint256 b_tag;
    BN254Point G;
    BN254Point H;
    BN254Point Com;
    BN254Point[5] L;
    BN254Point[5] R;
    BN254Point[32] g_vec; 
    BN254Point[32] h_vec;
}

contract Bulletproof {
    // State variable to store a number
    uint256 public num;
    BN254 public bn254= new BN254();
    uint8 pre = 0x04;
    uint32 zerobytes = 0x00;
    uint8 zerobyte = 0x00;

    uint256 gx = 0x01;
    uint256 gy = 0x02;

    uint256 basefield = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 order = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 constant bits_length = 32;
    uint256 constant lg_n = 5;
    uint256[31] lg_i = [0,1,1,2,2,2,2,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4];


    function reverse(uint256 input) internal pure returns (uint256 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        // swap 8-byte long pairs
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
    }
    
    function pushPointToHash(bytes memory b,BN254Point memory point) internal returns(bytes memory) {
        return abi.encodePacked(b,reverse(point.x),reverse(point.y));
        // return abi.encodePacked(b,pre,point.x,point.y);
    }
    function pushIntToHash(bytes memory b, uint256 x) internal returns(bytes memory) {
        return abi.encodePacked(b,x);
    }
    function closeHash(bytes memory b) internal returns (uint256){
        return uint256(sha256(abi.encodePacked(b, zerobytes))) % order;
        // uint256(sha256(closeHash(b))) % order
        // return  abi.encodePacked(b, zerobyte,zerobyte,zerobyte,zerobyte);
    }

   function emptytest(BN254Point calldata point1, uint256 scalar) public returns (BN254Point memory){
        return point1;
    }
    function emptytest2(BN254Point calldata point1, BN254Point calldata point2) public returns (BN254Point memory){
        return point1;
    }
    function addtest(BN254Point calldata point1, BN254Point calldata point2) public returns (BN254Point memory){
        return bn254.add(point1, point2);
    }      
    function addtest2(BN254Point calldata point1, BN254Point calldata point2) public returns (BN254Point memory){
        return bn254.add(bn254.add(point1, point2), point2);
    }
    function multest(BN254Point calldata point1, uint256 scalar) public returns (BN254Point memory){
        return bn254.mul(point1, scalar);
    }
    function multest2(BN254Point calldata point1, uint256 scalar) public returns (BN254Point memory){
        return bn254.mul(bn254.mul(point1, scalar),scalar);
    }

    function iterate(uint256 step) internal returns (uint256[bits_length] memory arr){
        arr[0] = 1;
        for (uint8 counter=1; counter< bits_length; counter++){
            arr[counter] = mulmod(arr[counter-1],step,order);
        }
    }
    function iterate_sum(uint256[bits_length] memory arr, uint256 length) internal returns (uint256){
        uint256 fold = arr[0];
        for (uint8 counter=1; counter< bits_length; counter++){
            fold =  addmod(fold, arr[counter], order);
        }
        return fold;
    }

    //https://github.com/witnet/elliptic-curve-solidity/blob/master/contracts/EllipticCurve.sol
    function inv(uint256 _x) internal returns (uint256) {
        require(_x != 0 && _x != order, "Invalid number");
        uint256 q = 0;
        uint256 newT = 1;
        uint256 r = order;
        uint256 t;
        while (_x != 0) {
            t = r / _x;
            (q, newT) = (newT, addmod(q, (order - mulmod(t, newT, order)), order));
            (r, _x) = (_x, r - t * _x);
        }
        return q;
    }


    function verify_range_proof(Rangeproof calldata proof) public returns (uint256, uint256){
        // bytes memory b = abi.encodePacked(pre,proof.A.x,proof.A.y);
        bytes memory b = abi.encodePacked(reverse(proof.A.x),reverse(proof.A.y));
        uint256 y = closeHash(pushPointToHash(b, proof.S));
        BN254Point memory yG = bn254.mul(BN254Point(gx,gy), y);

        b = "";
        uint256 z = closeHash(pushPointToHash(b, yG)); 

        b = "";
        b= pushPointToHash(b, proof.T1);
        b= pushPointToHash(b, proof.T2);
        b= pushPointToHash(b, proof.G);
        uint256 u_fs_challenge= closeHash(pushPointToHash(b, proof.H));
        uint256[bits_length] memory yi = iterate(y);
        uint256[bits_length] memory vec2n =  iterate(2);
        {
            // Check for eq65.
            uint256 z_square = mulmod(z,z,order);
            uint256 z_square_minus = order - z_square;
            BN254Point memory t1u = bn254.mul(proof.T1,u_fs_challenge);
            BN254Point memory t2u2 = bn254.mul(proof.T2,mulmod(u_fs_challenge,u_fs_challenge,order));
            BN254Point memory vz2 = bn254.mul(proof.Com, z_square);
            BN254Point memory deltayz = bn254.mul(proof.G,( mulmod(iterate_sum(yi, bits_length), ((z + z_square_minus)%order), order) + (order - mulmod(iterate_sum(vec2n, bits_length),mulmod(z_square,z,order),order))  )%order) ; 
            BN254Point memory RHS = bn254.add(bn254.add(bn254.add(deltayz,vz2), t1u),t2u2);
            BN254Point memory LHS = bn254.add(bn254.mul(proof.G,proof.tx),bn254.mul(proof.H,proof.tau_x));
            require(LHS.x == RHS.x && LHS.y == RHS.y);
        }


        b = "";
        b= pushIntToHash(b, proof.tau_x);
        b= pushIntToHash(b, proof.miu);
        BN254Point memory G_challenge_x= bn254.mul(proof.G, closeHash(pushIntToHash(b, proof.tx)));
        BN254Point memory P = bn254.add(bn254.add(bn254.add(bn254.mul(proof.H, order - proof.miu), bn254.mul(G_challenge_x, proof.tx)), proof.A), bn254.mul(proof.S, u_fs_challenge));
        
        BN254Point[bits_length] memory hi;
        for (uint256 counter = 0;counter<bits_length;counter++){
            hi[counter] = bn254.mul(proof.h_vec[counter], inv(yi[counter]));
        }

        // Computing P
        {
            // P, hi, yi, z, vec2n, bits_length == count
            for (uint256 counter = 0; counter< bits_length; counter++){
                // j==0 for single
                // k = counter% bits_length, k==counter for single
                uint256 zyn_zsq2n = addmod(mulmod(mulmod(z, z, order),vec2n[counter],order), mulmod(z, yi[counter], order), order);
                // uint256 zyn_zsq2n = (mulmod(modExp(z, 2+0, order),vec2n[counter],order)+ mulmod(z, yi[counter], order)) % order;
                P = bn254.add(P, bn254.mul(hi[counter], zyn_zsq2n));
            }
            uint256 z_minus = order - z;
            for (uint256 counter = 0; counter< bits_length; counter++){
                P = bn254.add(P, bn254.mul(proof.g_vec[counter], z_minus));
            }            
        }

        //IPA
        BN254Point memory ux_c = bn254.mul(G_challenge_x, mulmod(proof.a_tag, proof.b_tag, order));
        BN254Point[bits_length] memory G = proof.g_vec;
        {
            BN254Point memory P_tag = P;
            uint256 n = bits_length;

            uint256 loop_counter =0;
            while (n!=1){
                n = n/2;
                
                b = "";
                b= pushPointToHash(b, proof.L[loop_counter]);
                b= pushPointToHash(b, proof.R[loop_counter]);
                uint256 x=  closeHash(pushPointToHash(b, G_challenge_x));
                uint256 x_sq = mulmod(x,x,order);
                uint256 x_inv = inv(x);
                uint256 x_inv_sq = mulmod(x_inv,x_inv,order);

                for (uint256 inner_counter=0; inner_counter<n;inner_counter++){
                    G[inner_counter] = bn254.add(bn254.mul(G[inner_counter], x_inv),bn254.mul(G[n+inner_counter], x));
                    hi[inner_counter] = bn254.add(bn254.mul(hi[inner_counter], x),bn254.mul(hi[n+inner_counter], x_inv));
                }
                P_tag = bn254.add(bn254.add(bn254.mul(proof.L[loop_counter], x_sq), bn254.mul(proof.R[loop_counter],x_inv_sq)), P_tag);

                loop_counter +=1;
            }
            BN254Point memory P_calc = bn254.add(bn254.add(bn254.mul(G[0], proof.a_tag), bn254.mul(hi[0], proof.b_tag)), ux_c);
            require(P_calc.x == P_tag.x);
        }


        // // // IPA - Fast
        // uint256 allinv = 1;
        // BN254Point memory ux_c = bn254.mul(G_challenge_x, mulmod(proof.a_tag, proof.b_tag, order));
        // {
        //     uint256[lg_n] memory x_sq_arr;
        //     // uint256[lg_n] x_inv_sq_arr_to;
        //     uint256[lg_n] memory minus_xq_sq_arr;
        //     uint256[lg_n] memory minus_x_inv_sq_arr;
        //     for (uint256 counter = 0; counter< lg_n; counter++){
        //         b = "";
        //         b= pushPointToHash(b, proof.L[counter]);
        //         b= pushPointToHash(b, proof.R[counter]);
        //         uint256 x = closeHash(pushPointToHash(b, G_challenge_x));
        //         uint256 x_sq = mulmod(x,x,order);
        //         x_sq_arr[counter] = x_sq;
        //         uint256 x_inv = inv(x);
        //         minus_x_inv_sq_arr[counter] = order - mulmod(x_inv,x_inv,order);
        //         minus_xq_sq_arr[counter] = order - x_sq;

        //         allinv = mulmod(allinv,x_inv, order);
        //     }

        //     uint256[bits_length] memory s;
        //     s[0] = allinv;
        //     for (uint256 counter=1;counter<bits_length;counter++){
        //         uint256 k = (1 << lg_i[counter-1]);
        //         s[counter] = mulmod(s[counter-k], x_sq_arr[(lg_n-1) - lg_i[counter-1]], order);
        //     }

        //     uint256[bits_length] memory a_time_s;
        //     uint256[bits_length] memory b_div_s;
        //     for (uint256 counter=0;counter<bits_length;counter++){
        //         a_time_s[counter] = mulmod(s[counter], proof.a_tag, order);
        //         b_div_s[counter] = mulmod(inv(s[counter]),proof.b_tag,order);
        //     }

        //     //Multi Scalar Mul - MSM
        //     for (uint256 counter=0;counter<bits_length;counter++){
        //         ux_c = bn254.add(ux_c, bn254.add(bn254.mul(proof.g_vec[counter], a_time_s[counter]), bn254.mul(hi[counter], b_div_s[counter]) ) );
        //     }
        //     for (uint256 counter=0;counter<lg_n;counter++){
        //         ux_c = bn254.add(ux_c, bn254.add(bn254.mul(proof.L[counter], minus_xq_sq_arr[counter]), bn254.mul(proof.R[counter], minus_x_inv_sq_arr[counter]) ) );
        //     }
        // }
        // require(ux_c.x == P.x && ux_c.y == P.y);

        //////// return (ux_c.x,ux_c.y);

        return (1,1);

        
    }

    // You can read from a state variable without sending a transaction.
    function get() public view returns (uint256) {
        return num;
    }
}