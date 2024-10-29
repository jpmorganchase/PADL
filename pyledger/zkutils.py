"""
Util objects to wrap some of the zkbp module.
PADL - GTAR - London - JPMorgan
"""
import zkbp
from functools import reduce
import json
class r_blend:
    def __init__(self, val=None):
        if val == None:
            val = zkbp.gen_r()
        self.val = val

    def __get__(self):
        return self.val

    def get(self):
        return self.__get__()

    def to_str(self):
        return self.val.get

    def __add__(self, r2):
        val_sum = self.val.sum(r2.val)
        return r_blend(val_sum)

    def __sub__(self, r2):
        val_sub = self.val.sum(r2.val.neg())
        return r_blend(val_sub)

    def __mul__(self, n):
        c2 = self
        for i in range(1, n): 
            c2 = c2 + self
        return c2

    def __neg__(self):
        val_neg = self.val.neg()
        return r_blend(val_neg)

    def is_zero(self):
        return self.val.is_zero()
    


class Commit:
    def __init__(self, gh=None, value=None, r=None, eval=None):
        self.r = r
        self.gh = gh
        self.value = value
        if eval==None:
            self.eval = self.res()
        else:
            self.eval = eval

    def __add__(self, com):
        return Commit(eval=self.eval.sum(com.eval))

    def __sub__(self, com):
        return Commit(eval=self.eval.sub(com.eval))

    def __mul__(self, n):
        c2 = self
        for i in range(1, n):  
            c2 = c2 + self
        return c2

    def is_zero(self):
        return self.eval.is_zero()

    def res(self):
        return zkbp.commit(self.value, self.r.val, self.gh)
    
    def to_str(self):
       return zkbp.to_str()

    @staticmethod
    def from_str(s):
        return Commit(eval=zkbp.from_str(s))


class Token:
    def __init__(self, pbsk=None, r=None, eval=None):
        self.r = r
        self.pbsk = pbsk
        if eval==None:
            self.eval = self.res()
        else:
            self.eval = eval

    def __add__(self, token):
        return Token(eval=zkbp.add_token(self.eval, token.eval))

    def __sub__(self, token):
        return Token(eval=self.sub_token(self.eval, token.eval))

    def __mul__(self, n):
        c2 = self
        for i in range(1, n):  # improve to exponentiation
            c2 = c2 + self
        return c2

    def is_zero(self):
        return self.eval.is_zero()

    def res(self):
        return self.pbsk.to_token(self.r.get())
    
    def to_str(self):
       return zkbp.to_str()
    


    @staticmethod
    def from_str(s):
        return Token(eval=zkbp.to_token_from_str(s))


class Ledger:
    @staticmethod
    def sum_commits(tx_line):
        return reduce(lambda x, y: zkbp.add(x,y), tx_line)

class Secp256k1:
    gh = zkbp.gen_GH()
    @staticmethod
    def to_scalar_full(str_scalar):
        s0 = {"curve": "secp256k1",
              "scalar": "0"*64}
        if str_scalar[0:2] == "0x" and len(str_scalar) == 66:
            str_scalar = str_scalar[2:]
        if len(str_scalar) != 64:
            NotImplementedError("size need to be 64 hexadecimal")
        s0['scalar'] = str_scalar
        zkbp_scalar = zkbp.to_scalar_from_str(json.dumps(s0))
        return zkbp_scalar

    @staticmethod
    def to_scalar(str_scalar):
        if str_scalar[0:2] == "0x" and len(str_scalar) == 66:
            str_scalar = str_scalar[2:]
        if len(str_scalar) != 64:
            NotImplementedError("size need to be 64 hexadecimal")
        s0 = str_scalar
        zkbp_scalar = zkbp.to_scalar_from_str(s0)
        return zkbp_scalar

    @staticmethod
    def to_pk(secret_key):
        secret_scalar = Secp256k1.to_scalar(secret_key)
        sk_pk_obj = zkbp.regen_pb_sk(Secp256k1.gh, secret_scalar)
        return sk_pk_obj.get_pk()

    @staticmethod
    def isoncurve(pt,p):
        """
        returns True when pt is on the secp256k1 curve
        """
        (x,y)= pt
        return (y**2 - x**3 - 7)%p == 0

    @staticmethod
    def get_xy(compressed_point_str):
        p = 2**256 - 2**32 - 977

        if int(compressed_point_str, 16) == int(0):
            return (0,0)

        xcoor_str = compressed_point_str[2:]
        xcoor_int = (int(xcoor_str, base=16))
        assert p % 4 == 3
        ycoor_int = pow(((pow(xcoor_int,3,p) + 7) % p),((p+1)//4),p)
        if ycoor_int%2==0 and compressed_point_str[:2] == "02" or ycoor_int%2==1 and compressed_point_str[:2] == "03":
            #Even or odd do nothing
            None
        else:
            #Flip the odd-even parity
            ycoor_int = (-ycoor_int)%p

        if not Secp256k1.isoncurve((xcoor_int,ycoor_int), p):
            print(xcoor_int, " ; ", ycoor_int, " , ", compressed_point_str)
        assert Secp256k1.isoncurve((xcoor_int,ycoor_int), p)
        return (xcoor_int, ycoor_int)

    @staticmethod
    def get_pre_int_cm(c):
        if len(c) == 66:
            intcmtk = int('0x' + c[2:],16)
            if c[0:2] == '02':
                prefix = int('0x2',16)
            elif c[0:2] == '03':
                prefix = int('0x3',16)
            elif c[0:2] == '00':
                prefix = int('0x0',16)
            return (prefix,intcmtk)
    @staticmethod
    def get_ec_from_cells(p):
        cmx, cmy = Secp256k1.get_xy(p.cm)
        tkx, tky = Secp256k1.get_xy(p.token)
        return ((cmx,cmy),(tkx,tky))

    @staticmethod
    def get_ec_from_cells_pre(p):
        precmx, cmx = Secp256k1.get_pre_int_cm(p.cm)
        pretkx, tkx = Secp256k1.get_pre_int_cm(p.token)
        return ((precmx,cmx),(pretkx,tkx))

    @staticmethod
    def get_compressed_ecpoint(x, y):
        x = x.to_bytes(32,'big')
        y = y.to_bytes(32,'big')
        x_32 = (32 - len(x)) * b'\0' + x
        y_32 = (32 - len(y)) * b'\0' + y
        compressed = (b'\02' if y_32[31] % 2 == 0 else b'\03') + x_32
        #uncompressed = b'\04' + x_32 + y_32
        return str(compressed.hex())
    @staticmethod
    def to_scalar_from_zero(hex=64):
        return zkbp.to_scalar_from_str(str(0)*hex)