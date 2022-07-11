# VSCTF 2022 – Crypto Challenge

## Baby RSA (68 solves): 452 points

### Description/Source

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from secret import e

with open("flag.txt",'r') as f:
    flag = f.read().strip()

p = getPrime(128)
q = getPrime(128)

while p % e != 1:
    p = getPrime(128)
while q % e != 1:
    q = getPrime(128)

n = p * q
m = bytes_to_long(flag.encode())
c = pow(m, e, n)
print(f"Ciphertext: {hex(c)}")

with open("pubkey.pem",'w') as f:
    pk = RSA.construct([n, e])
    f.write(pk.exportKey('PEM').decode('utf-8'))
```

We have a `.pem` file which we can use to extract the modulus and exponent. The modulus is made out of 2 128 bit primes which can be easily factored. However, the exponent is a factor of both $p-1$ and $q-1$, which makes the standard decryption method invalid. However, given that the exponent is extremely small $e = 101$, we can simply iterate through all the nth roots of unity, until we find a possible flag.

Note: this is extremely similar to DiceCTF's challenge, also coined BabyRSA earlier this year. The solve script is practically the same as well. My writeup there is slightly more detailed. I also used the `python` script rather than `sage`

### Solver

```python
from random import randint
from libnum import n2s
from Crypto.PublicKey import RSA
f = open("pubkey.cer", "r")
key = RSA.importKey(f.read())


# n = 52419317100235286358057114349639882093779997394202082664044401328860087685103
# e = 101
n = key.n
e = key.e

ct = 0x459cc234f24a2fb115ff10e272130048d996f5b562964ee6138442a4429af847
p = 184980129074643957218827272858529362113
q = 283378097758180413812138939650885549231

phi = (p-1) *(q-1)//(e**2)
d = pow(e,-1,phi)
potential_pt = pow(ct,d,n)

def getGenerators():
    phi = (p-1) *(q-1)//(e**2)
    g1 = pow(randint(1,n-1),phi,n) #most any number will work
    g2 = pow(randint(1,n-1),phi,n)
    assert pow(g1,e,n) == 1 # order of generator is e
    assert pow(g2,e,n) == 1
    return g1,g2


def decode(g1,g2):
    for i in range(e):
        for j in range(e):
            x,y = pow(g1,i,n), pow(g2,j,n) #cycles through all members of the group with order e in the generator
            flag_num = (potential_pt*x*y) %n
            flag = n2s(flag_num)
            if(b'vsctf' in flag):
                print(flag)
                return
g1,g2 = getGenerators()
decode(g1,g2)
```

### Flag

```
vsctf{5m411_Pr1m3_15_Un54f3!}
```
