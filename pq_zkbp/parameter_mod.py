from Crypto.Util import number

from random import randint
import math
import sympy as sp
from sympy.ntheory import primitive_root, is_primitive_root
from functools import reduce

degree = 1024
l_degree = 512
qbit = 127

def generate_ntt_prime_notfull(qbit, s_slot,degree):
    mod = number.getPrime(qbit)
    count = 0 
    
    temp_degree = 2 * degree
    test_degree = [temp_degree]
    temp_degree /= 2
    temp_degree = temp_degree.__ceil__()
    while temp_degree != 2* s_slot:
        test_degree.append(temp_degree)
        temp_degree /= 2
        temp_degree = temp_degree.__ceil__()
    print(test_degree)
    while (mod% (2*s_slot) != 1) or reduce(lambda x,y : x or y, map (lambda degree: mod % degree == 1, test_degree)):
        count +=1 
        mod = number.getPrime(qbit)
    assert mod%(2*s_slot) == 1
    return mod

def legendre(a,p):
    return pow(a, (p-1)//2,p)

def tonelli(n,p):
    assert legendre(n,p) == 1, "not a square (mod p)"
    q = p-1
    s = 0
    while q%2==0:
        q //= 2
        s+=1
    if s==1:
        return pow (n, (p+1)//4, p)
    for z in range(2,p):
        if p-1 == legendre(z,p):
            break
    c = pow(z,q,p)
    r = pow(n, (q+1)//2, p)
    t = pow(n,q,p)
    m = s
    t2 = 0
    while (t-1)% p !=0:
        t2 = (t*t) % p
        for i in range(1,m):
            if (t2 - 1 )% p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1<< (m-i-1), p)
        r = (r*b) %p
        c = (b*b) %p
        t = (t*c) % p
        m= i
    return r

def factors(n):
    return list(reduce(list.__add__, ([i, n//i] for i in range(1, int(n**0.5)+1) if n%i==0)))

#degree = d, s_slot_degree = l
def gen_param(qbit, degree, s_slot_degree):
    nbits = math.log2(degree).__ceil__()
    assert 2**nbits==degree
    
    def gen_n_primitive_root(n, modulus):
        CNUM_factors = factors(n)
        CNUM_factors.remove(1)
        CNUM_factors.remove(n)
        assert (modulus-1)%n == 0
        guess_g = 0
        
        is_correct_g = False
        while not is_correct_g:
            is_correct_g= True
            x = randint(2,modulus-1)
            guess_g = pow(x, (modulus-1)//n, modulus)
            for factor in CNUM_factors:
                if pow(guess_g, factor, modulus) == 1:
                    is_correct_g = False
        # print(guess_g)
        return guess_g
    
    MODULUS = generate_ntt_prime_notfull(qbit, s_slot_degree, degree)
    assert(MODULUS % (2*s_slot_degree)) == 1
    temp_degree = 2*degree
    while temp_degree  != 2*(s_slot_degree):
        if MODULUS % temp_degree == 1:
            print (temp_degree, "splitted further")
        temp_degree //= 2
        
    print("MODULUS Q :", MODULUS)
    GEN_D = gen_n_primitive_root(s_slot_degree, MODULUS)
    assert pow(GEN_D, s_slot_degree, MODULUS) == 1
    for i in range(1, s_slot_degree-1):
        assert pow(GEN_D, i, MODULUS) != 1
        
    GEN_2D = tonelli(GEN_D, MODULUS)
    for i in range(1, 2*s_slot_degree):
        assert pow(GEN_2D, i, MODULUS) != 1
    assert pow(GEN_2D, 2*s_slot_degree, MODULUS) == 1
    # assert pow(GEN_2D, 4*s_slot_degree, MODULUS) == 1
    
    print("primitive l-root=", GEN_D)
    print("primitive 2l-root=", GEN_2D)
    
    print("generator: ", primitive_root(qbit))
    
gen_param(qbit, degree, l_degree)