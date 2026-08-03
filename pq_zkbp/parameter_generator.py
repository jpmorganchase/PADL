from Crypto.Util import number
import math

# Parameter generated based on hardness of SIS and LWE 

# Assuming we have generated relevant 2l_root, modulus, degree, l already.
# QBITS = 63
# MODULUS = 5732819311601719681 #2**63 bits ish, to fit into 64-bit register and multiplication would require i128 instruction support.
# DEGREE = 128 #Number of coeffient = 128, (X mod 2**Degree+1 )
# L = 64
# ROOT_2L = 1865432272857165791

# # This is used to get performance for Q=100 in the paper, d=256, we set q=127 for maximum q under 128 bits, should not affect performance
# QBITS = 127
# MODULUS = 400248081349031544323182926593
# DEGREE = 256 #Number of coeffient = 128, (X mod 2**Degree+1 )
# L = 128
# ROOT_2L = 381834999758160791421264820604

# # This is used to get performance for Q=100 in the paper, d=1024
QBITS = 100
MODULUS = 1069041947296804094810040343553
DEGREE = 1024 
L = 512
ROOT_2L = 163533728772853032652927408329

FULL_LAYERS = int(math.log2(DEGREE))
assert 2**FULL_LAYERS == DEGREE
NUM_LAYERS = int(math.log2(L))
assert 2**NUM_LAYERS == L


# Various condition for testing
assert number.isPrime(MODULUS)
for i in range(1,2*L):
    assert pow(ROOT_2L,i,MODULUS) != 1
assert pow(ROOT_2L, 2*L, MODULUS) == 1
assert (MODULUS %(4*L)) == 2*L +1 #

# Rejection Sampling Parameter 
REJ_M = 3.0

# Now Generate NTT Twiddle Factor, the following function is modified from https://github.com/mkannwischer/polymul
def bitreverse(a):
    b = [0]*len(a)
    logn =  int(math.log(len(a), 2))
    assert 2**logn == len(a)

    def bitrevidx(a, nbits):
        fmt = f"{{0:0{nbits}b}}"
        return list(map(lambda x: int(fmt.format(x)[::-1],2), a))

    brv = bitrevidx(list(range(len(a))), logn)

    for i in range(len(a)):
        b[brv[i]] = a[i]
    return b

def precomp_ct_negacyclic(n, root, q, numLayers):
    logn =  int(math.log(n, 2))
    assert 2**logn == n
    twiddles = [pow(root, i, q) for i in range(2**numLayers)]
    twiddles = bitreverse(twiddles)
    twiddlesPerLayer = []
    off = 1
    for i in range(numLayers):
        twiddlesPerLayer.extend(twiddles[off:off+2**i])
        off = off+2**i

    return twiddlesPerLayer

def precomp_basemul_negacyclic (n, root, q, numLayers):
    logn =  int(math.log(n, 2))
    assert 2**logn == n
    assert numLayers <= logn

    twiddles = [pow(root, 2*i+1, q) for i in range(2**numLayers)]
    twiddles = bitreverse(twiddles)
    return twiddles

def precomp_gs_negacyclic(n, root, q, numLayers):
    logn =  int(math.log(n, 2))
    assert 2**logn == n
    twiddles = [pow(root, -(i+1), q) for i in range(2**numLayers)]
    twiddles = bitreverse(twiddles)

    twiddlesPerLayer = []
    off = 0
    for i in range(logn-numLayers, logn):
        twiddlesPerLayer.extend(twiddles[off:off+2**(logn-1-i)])
        off = off+2**(logn-1-i)

    return twiddlesPerLayer


# Now generate montgomery factor for montgomery reduction. (This give about 2x Performance gains for polymul accounting for domain conversion both ways.)
import math
import random
def montgomery_parameter(n_mod):
    n_bits = n_mod.bit_length()
    
    r_mod = None
    
    for i in range(1, 128-n_bits):
        try_rmod = 2**(n_bits+i)
        if (math.gcd(try_rmod, n_mod) == 1):
            r_mod = try_rmod
            break
        
    r_mod_inv = pow(r_mod,-1,n_mod)
    
    assert (((r_mod*r_mod_inv)-1)/n_mod).is_integer()
    n_mod_prime = ((r_mod*r_mod_inv)-1)//n_mod
    
    # print(f"r_mod:{r_mod}, RMOD_BIT_SHIFT = {r_mod.bit_length()-1}, RMOD_MODULO_MASK = {r_mod-1}, n_mod_prime: {n_mod_prime}",)
    MODR_BIT_SHIFT = r_mod.bit_length()-1
    MODR_MASK = r_mod -1
    
    def reduce(x, r_mod, n_mod, n_mod_prime):
        assert (x <= (n_mod*r_mod-1))
        temp_q = ((x&MODR_MASK) * n_mod_prime) & MODR_MASK # r_mod should be implemented with bit masking with (r_mod-1) because r_mod is of the form 0b1000...
        assert ( ((x) + (temp_q*n_mod)) / r_mod).is_integer()
        a = ((x) + (temp_q*n_mod)) >> MODR_BIT_SHIFT #right bit shift by b where 2**b = r_mod
        if a >= n_mod:
            a = a-n_mod
        assert 0 <= a < n_mod
        return a
        
    num1 = random.randint(0, n_mod)
    num2 = random.randint(0, n_mod)
    num1R = (num1 * r_mod) % n_mod
    num2R = (num2 * r_mod) % n_mod
    
    num12RR = num1R * num2R
    num12R = reduce(num12RR, r_mod, n_mod,n_mod_prime)
    
    assert num12R == ( (num1*num2*r_mod) % n_mod)
    num12 = reduce(num12R, r_mod, n_mod,n_mod_prime)
    
    assert (num12 == ((num1*num2) % n_mod))
    
    assert 2**(r_mod.bit_length()-1) == r_mod
    return r_mod, r_mod_inv, MODR_BIT_SHIFT, MODR_MASK, n_mod_prime
    
RMOD, RMOD_INV, RMOD_BIT_SHIFT, RMOD_MODULO_MASK, NMOD_PRIME = montgomery_parameter(MODULUS)
print(RMOD_MODULO_MASK.bit_length())
assert RMOD_MODULO_MASK.bit_length() <= 128, "Currently assumed mask fit into 128-bit" 
# assert RMOD_MODULO_MASK.bit_length() == 64, "Currently assumed mask fit into 64-bit" 

NINV = pow(2**NUM_LAYERS, -1, MODULUS)

print(f"pub const MODULUS: u128 = {MODULUS};")
print(f"pub const MODULUS_MINUS1_OVER2: u128 = {(MODULUS-1)//2};")
print(f"pub const MODULUS_I128: i128 = {MODULUS};")
# print(f"pub const MODULUS_128: u128 = {MODULUS};")
print(f"pub const MODULUS_SQRT: u128 = {round(math.sqrt(MODULUS))};")
sqrt_q = round(math.sqrt(MODULUS))
sqrt_q_inv = pow(sqrt_q, -1, MODULUS)
assert ((sqrt_q*sqrt_q_inv) % MODULUS) == 1
print(f"pub const MODULUS_SQRT_INV: u128 = {sqrt_q_inv};")
print(f"pub const DEGREE: usize = {DEGREE};")
print(f"pub const BASEMUL_DEGREE: usize = {2**(FULL_LAYERS-NUM_LAYERS)};")
print(f"pub const L: u32 = {L};")
print(f"pub const FULL_LAYERS: u32 = {FULL_LAYERS};")
print(f"pub const NUM_LAYERS: u32 = {NUM_LAYERS};")
print(f"pub const ROOT_2L_NON: u128 = {ROOT_2L};")
print(f"pub const NINV_NON: u128 = {NINV};")
twiddlesNTT = precomp_ct_negacyclic(DEGREE, ROOT_2L, MODULUS, NUM_LAYERS)
print(f"pub const CT_TWIDDLE_NON: [u128; {len(twiddlesNTT)}] = {twiddlesNTT};")
twiddlesInvNTT = precomp_gs_negacyclic(DEGREE, ROOT_2L, MODULUS, NUM_LAYERS)
print(f"pub const GS_TWIDDLE_NON: [u128; {len(twiddlesInvNTT)}] = {twiddlesInvNTT};")
twiddlesBaseMul = precomp_basemul_negacyclic(DEGREE, ROOT_2L, MODULUS, NUM_LAYERS)
print(f"pub const BM_TWIDDLE_NON: [u128; {len(twiddlesBaseMul)}] = {twiddlesBaseMul};")

# Parameter with Montgomery Factor precomputed
def convert_arr_into_mont(arr, r_mod, mod):
    return [(item*r_mod) % mod for item in arr]

assert NINV * RMOD == NINV << RMOD_BIT_SHIFT

print()
print(f"pub const REJ_M: f64 = {REJ_M};")

print()
print(f"pub const RMOD_INV: u128 = {RMOD_INV};")
print(f"pub const RMOD_BIT_SHIFT: u128 = {RMOD_BIT_SHIFT};")
print(f"pub const RMOD_MODULO_MASK: u128 = {RMOD_MODULO_MASK};")
print(f"pub const NMOD_PRIME: u128 = {NMOD_PRIME};")
print(f"pub const NINV_M: u128 = {(NINV * RMOD) % MODULUS};")
twiddlesNTT = precomp_ct_negacyclic(DEGREE, ROOT_2L, MODULUS, NUM_LAYERS)
twiddlesNTT = convert_arr_into_mont (twiddlesNTT, RMOD, MODULUS)
print(f"pub const CT_TWIDDLE_M: [u128; {len(twiddlesNTT)}] = {twiddlesNTT};")
twiddlesInvNTT = precomp_gs_negacyclic(DEGREE, ROOT_2L, MODULUS, NUM_LAYERS)
twiddlesInvNTT = convert_arr_into_mont (twiddlesInvNTT, RMOD, MODULUS)
print(f"pub const GS_TWIDDLE_M: [u128; {len(twiddlesInvNTT)}] = {twiddlesInvNTT};")
twiddlesBaseMul = precomp_basemul_negacyclic(DEGREE, ROOT_2L, MODULUS, NUM_LAYERS)
twiddlesBaseMul = convert_arr_into_mont (twiddlesBaseMul, RMOD, MODULUS)
print(f"pub const BM_TWIDDLE_M: [u128; {len(twiddlesBaseMul)}] = {twiddlesBaseMul};")
