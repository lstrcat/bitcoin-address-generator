import os
import hashlib
import time
import random


def sha256(data):
        digest = hashlib.new("sha256")    
        digest.update(data)    
        return digest.digest()

def ripemd160(x):    
    d = hashlib.new("ripemd160")    
    d.update(x)    
    return d.digest()

def b58(data):    
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if data[0] == 0:        
         return "1" + b58(data[1:])
    x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])    
    ret = ""    
    while x > 0:        
        ret = B58[x % 58] + ret        
        x = x // 58
    return ret

class Point:    
    def __init__(self,        
                 x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,        
                 y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,        
                 p=2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1):        
                 self.x = x        
                 self.y = y        
                 self.p = p
    def __add__(self, other):        
         return self.__radd__(other)
    def __mul__(self, other):        
         return self.__rmul__(other)
    def __rmul__(self, other):        
        n = self        
        q = None
        for i in range(256):            
            if other & (1 << i):                
                q = q + n            
            n = n + n
        return q
    def __radd__(self, other):        
        if other is None:            
            return self        
        x1 = other.x        
        y1 = other.y        
        x2 = self.x        
        y2 = self.y        
        p = self.p
        if self == other:            
            l = pow(2 * y2 % p, p-2, p) * (3 * x2 * x2) % p        
        else:            
            l = pow(x1 - x2, p-2, p) * (y1 - y2) % p
        newX = (l ** 2 - x2 - x1) % p        
        newY = (l * x2 - l * newX - y2) % p
        return Point(newX, newY)
    def toBytes(self):        
        x = self.x.to_bytes(32, "big")        
        y = self.y.to_bytes(32, "big")        
        return b"\x04" + x + y
    def toBytesCompressed(self):
        x = self.x.to_bytes(32, "big")
        # 判断y是奇数还是偶数
        # 前缀03+x(如果y是奇数)，前缀02+x(如果y是偶数)
        y = self.y.to_bytes(32, "little")
        e = y[0]
        if e % 2 == 0:
            return b"\x02" + x
        else:
            return b"\x03" + x
def getPublicKey(privkey):    
    SPEC256k1 = Point()    
    pk = int.from_bytes(privkey, "big")    
#    hash160 = ripemd160(sha256((SPEC256k1 * pk).toBytes()))    
    hash160 = ripemd160(sha256((SPEC256k1 * pk).toBytesCompressed()))   
    address = b"\x00" + hash160
    address = b58(address + sha256(sha256(address))[:4])    
    return address
def getWif(privkey):    
#    wif = b"\x80" + privkey
    wif = b"\x80" + privkey    + b"\x01"
    wif = b58(wif + sha256(sha256(wif))[:4])    
    return wif



if __name__ == "__main__":    


    user_input = input("我想要钱包地址以它结尾:")

    with open('example.txt', 'a') as file:
        file.write('Hello, World!\n')

    i = 0
    while(1):
        i = i+1
        print(f'\r{i}', end='')
        randomBytes = os.urandom(32)    
        str = getPublicKey(randomBytes)
        if str.endswith(user_input):
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print("\r")
            print(current_time + "-钱包地址:" + str)
            print(current_time + "-钱包私钥:" + getWif(randomBytes))
        #    with open('example.txt', 'a') as file:
        #        file.writelines(current_time + "-钱包地址:" + str +'\n')
        #        file.writelines(current_time + "-钱包私钥:" + getWif(randomBytes) + '\n')
         
