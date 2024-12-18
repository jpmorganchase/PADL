// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./bn254__.sol";

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
    // BN254Point[32] yi_vec;
}

contract Bulletproof {
    // State variable to store a number
    uint256 public num;
    BN254 public bn254= new BN254();
    uint32 zerobytes = 0x00;

    uint256 gx = 0x01;
    uint256 gy = 0x02;

    uint256 basefield = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 order = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 constant bits_length = 32;
    uint256 constant lg_n = 5;
    uint256[31] lg_i = [0,1,1,2,2,2,2,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4];
    
    function pushPointToHash(bytes memory b,BN254Point memory point) internal returns(bytes memory) {
        return abi.encodePacked(b,point.y,point.x);
    }
    function pushPointToHash3(BN254Point memory point1,BN254Point memory point2,BN254Point memory point3 ) internal returns(bytes memory) {
        return abi.encodePacked(point1.y,point1.x,point2.y,point2.x,point3.y,point3.x);
    }
    function pushIntToHash(bytes memory b, uint256 x) internal returns(bytes memory) {
        return abi.encodePacked(b,x);
    }
    function closeHash(bytes memory b) internal returns (uint256){
        return uint256(sha256(abi.encodePacked(b, zerobytes))) % order;
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
    function iterate_with_sum(uint256 step) internal returns (uint256[bits_length] memory arr, uint256){
        arr[0] = 1;
        uint256 fold = 1;
        for (uint8 counter=1; counter< bits_length; counter++){
            arr[counter] = mulmod(arr[counter-1],step,order);
            fold = addmod(fold, arr[counter], order);
        }
        return (arr, fold);
    }
    // function iterate_sum(uint256[bits_length] memory arr, uint256 length) internal returns (uint256){
    //     uint256 fold = arr[0];
    //     for (uint8 counter=1; counter< bits_length; counter++){
    //         fold =  addmod(fold, arr[counter], order);
    //     }
    //     return fold;
    // }

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
        bytes memory b = "";
        b = pushPointToHash(b, proof.A);
        uint256 y = closeHash(pushPointToHash(b, proof.S));
        BN254Point memory yG = bn254.mul(BN254Point(gx,gy), y);

        b = "";
        uint256 z = closeHash(pushPointToHash(b, yG)); 

        b = "";
        b= pushPointToHash(b, proof.T1);
        b= pushPointToHash(b, proof.T2);
        b= pushPointToHash(b, proof.G);
        uint256 u_fs_challenge= closeHash(pushPointToHash(b, proof.H));
        uint256[bits_length] memory yi;
        uint256 yi_sum;
        (yi, yi_sum) = iterate_with_sum(y);
        uint256[bits_length] memory yi_inv = iterate(inv(y));
        uint256[bits_length] memory vec2n;
        uint256 vec2n_sum;
        (vec2n, vec2n_sum) =  iterate_with_sum(2);
        uint256 z_square = mulmod(z,z,order);
        {
            // Check for eq65.
            uint256 z_square_minus = order - z_square;
            BN254Point memory t1u = bn254.mul(proof.T1,u_fs_challenge);
            BN254Point memory t2u2 = bn254.mul(proof.T2,mulmod(u_fs_challenge,u_fs_challenge,order));
            BN254Point memory vz2 = bn254.mul(proof.Com, z_square);
            BN254Point memory deltayz = bn254.mul(proof.G,( mulmod(yi_sum, ((z + z_square_minus)%order), order) + (order - mulmod(vec2n_sum,mulmod(z_square,z,order),order))  )%order) ; 
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
            hi[counter] = bn254.mul(proof.h_vec[counter], yi_inv[counter]);
        }

        // Computing P
        {
            // P, hi, yi, z, vec2n, bits_length == count
            uint256 z_minus = order - z;
            BN254Point memory g_vec_sum = proof.g_vec[0];
            for (uint256 counter = 0; counter< bits_length; counter++){
                // j==0 for single
                // k = counter% bits_length, k==counter for single
                uint256 zyn_zsq2n = addmod(mulmod(z_square,vec2n[counter],order), mulmod(z, yi[counter], order), order);
                // uint256 zyn_zsq2n = (mulmod(modExp(z, 2+0, order),vec2n[counter],order)+ mulmod(z, yi[counter], order)) % order;
                P = bn254.add(P, bn254.mul(hi[counter], zyn_zsq2n));
            }
            for (uint256 counter=1; counter<bits_length;counter++){
                g_vec_sum = bn254.add(g_vec_sum, proof.g_vec[counter]); //presum this -100k
            }
            P = bn254.add(P, bn254.mul(g_vec_sum, z_minus));

            // for (uint256 counter = 0; counter< bits_length; counter++){
            //     //TODO: sum g_vec then only multiply z_minus once.
            //     P = bn254.add(P, bn254.mul(proof.g_vec[counter], z_minus));
            // }            
        }

        //IPA
        // BN254Point memory ux_c = bn254.mul(G_challenge_x, mulmod(proof.a_tag, proof.b_tag, order));
        // BN254Point[bits_length] memory G = proof.g_vec;
        // {
        //     BN254Point memory P_tag = P;
        //     uint256 n = bits_length;

        //     uint256 loop_counter =0;
        //     while (n!=1){
        //         n = n/2;
                
        //         b = "";
        //         b= pushPointToHash(b, proof.L[loop_counter]);
        //         b= pushPointToHash(b, proof.R[loop_counter]);
        //         uint256 x=  closeHash(pushPointToHash(b, G_challenge_x));
        //         uint256 x_sq = mulmod(x,x,order);
        //         // uint256 x_inv = (x); #300k
        //         uint256 x_inv = inv(x);
        //         uint256 x_inv_sq = mulmod(x_inv,x_inv,order);

        //         for (uint256 inner_counter=0; inner_counter<n;inner_counter++){
        //             G[inner_counter] = bn254.add(bn254.mul(G[inner_counter], x_inv),bn254.mul(G[n+inner_counter], x));
        //             hi[inner_counter] = bn254.add(bn254.mul(hi[inner_counter], x),bn254.mul(hi[n+inner_counter], x_inv));
        //         }
        //         P_tag = bn254.add(bn254.add(bn254.mul(proof.L[loop_counter], x_sq), bn254.mul(proof.R[loop_counter],x_inv_sq)), P_tag);

        //         loop_counter +=1;
        //     }
        //     BN254Point memory P_calc = bn254.add(bn254.add(bn254.mul(G[0], proof.a_tag), bn254.mul(hi[0], proof.b_tag)), ux_c);
        //     require(P_calc.x == P_tag.x);
        // }


        // IPA - Fast
        uint256 allinv = 1;
        BN254Point memory ux_c = bn254.mul(G_challenge_x, mulmod(proof.a_tag, proof.b_tag, order));
        {
            uint256[lg_n] memory x_sq_arr;
            uint256[lg_n] memory x_inv_sq_arr;
            for (uint256 counter = 0; counter< lg_n; counter++){
                uint256 x = closeHash(pushPointToHash3(proof.L[counter],proof.R[counter], G_challenge_x));
                uint256 x_sq = mulmod(x,x,order);
                x_sq_arr[counter] = x_sq;
                uint256 x_inv = inv(x);
                x_inv_sq_arr[counter] = mulmod(x_inv,x_inv,order);

                ux_c = bn254.add(ux_c, bn254.add(bn254.mul(proof.L[counter], order - x_sq), bn254.mul(proof.R[counter], order - x_inv_sq_arr[counter]) ) );

                allinv = mulmod(allinv,x_inv, order);
            }

            uint256[bits_length] memory s;
            s[0] = allinv;
            uint256[bits_length] memory s_inv;
            s_inv[0] = inv(allinv);
            ux_c = bn254.add(ux_c, bn254.add(bn254.mul(proof.g_vec[0],  mulmod(s[0], proof.a_tag, order)), bn254.mul(hi[0],mulmod((s_inv[0]),proof.b_tag,order)) ) );
            for (uint256 counter=1;counter<bits_length;counter++){
                uint256 k = (1 << lg_i[counter-1]);
                s[counter] = mulmod(s[counter-k], x_sq_arr[(lg_n-1) - lg_i[counter-1]], order);
                s_inv[counter] = mulmod(s_inv[counter-k], x_inv_sq_arr[(lg_n-1) - lg_i[counter-1]], order);

                ux_c = bn254.add(ux_c, bn254.add(bn254.mul(proof.g_vec[counter],  mulmod(s[counter], proof.a_tag, order)), bn254.mul(hi[counter],mulmod(s_inv[counter],proof.b_tag,order)) ) );
            }
            require(ux_c.x == P.x && ux_c.y == P.y);


            // uint256[bits_length] memory a_time_s;
            // uint256[bits_length] memory b_div_s;
            // for (uint256 counter=0;counter<bits_length;counter++){
            //     a_time_s[counter] = mulmod(s[counter], proof.a_tag, order);
            //     b_div_s[counter] = mulmod((s_inv[counter]),proof.b_tag,order);
            //     // b_div_s[counter] = mulmod(inv(s[counter]),proof.b_tag,order);
            // }
            //Multi Scalar Mul - MSM
            // for (uint256 counter=0;counter<bits_length;counter++){
            //     ux_c = bn254.add(ux_c, bn254.add(bn254.mul(proof.g_vec[counter],  a_time_s[counter], bn254.mul(hi[counter],b_div_s[counter]) ) );
            // }
            // require(ux_c.x == P.x && ux_c.y == P.y);
        }

        //////// return (ux_c.x,ux_c.y);

        return (1,1);

        
    }

}