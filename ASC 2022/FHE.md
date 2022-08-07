## Crypto Challenge: FHE

### Description/Source

```py
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, isPrime, getRandomNBitInteger
from random import getrandbits, randint

LEN = 25
BITS = 256

with open('flag.txt', 'rb') as file:
    FLAG = file.read()

bin_flag = bin(bytes_to_long(FLAG))[2:]

def gen():
    _p = 1
    while not isPrime(_p):
        _p = 2**255 + 2**127 + getRandomNBitInteger(LEN)
    pub = []
    for _ in range(LEN):
        r, q = getrandbits(BITS//2), getrandbits(BITS)
        pub.append(_p*q + 2*r)
    return pub, _p

def encrypt(public, bins):
    ciphertext = []
    for bit in bins:
        ids = [public[randint(0, len(public)-1)] for _ in range(5)]
        r = getrandbits(BITS//2)
        ciphertext.append(sum(ids) + 2*r + int(bit))
    return ciphertext

public, secret = gen()
ct = encrypt(public, bin_flag)

with open('output.txt', 'w') as h:
    for c in ct:
        h.write(str(c)+"\n")

```

After googling around the method of encryption, it can be seen that this is DGHV method of [encryption](https://github.com/coron/fhe)

Each bit of the flag is encrypted in this fashion, where $m_i$ is the bit of the cipher text and $q_i$ is a random number of 256 bits and $r_i$ is a smaller random number of 128 bits.

$$
c_i = q_ip + 2r_i + m_i
$$

$p$ is the secret key which is a 256 bit prime. If we can recover $p$, we can recover $m_i$ by taking

$$
m_i = (c_i \bmod p) \bmod 2
$$

And we can see that the prime $p$ can be brute forced because of this line here

```py
LEN = 25
while not isPrime(_p):
    _p = 2**255 + 2**127 + getRandomNBitInteger(LEN)
```

So $p$ is in the range $[2^{255} + 2^{127} + 2^{24}, 2^{255} + 2^{127} + 2^{25}-1]$, which means just another brute force solution. This would take in worst case ~ 45 mins.

### Solver

```python
from libnum import *
from tqdm import trange

from sympy import sieve

base = 2**255 + 2**127
# primes = list(sieve.primerange(base+2**23,base+2**24-1))

cts = []
with open('output.txt', 'r') as f:
    for line in f.readlines():
        cts.append(eval(line))


def QuotientNear(a,b):
#   "Gives the nearest integer to a/b"
  return (2*a+b)//(2*b)

def modNear(a,b):
#   "Computes a mod b with a \in ]-b/2,b/2]"
  return a-b*QuotientNear(a,b)

def decrypt(p,verbose=False):
    b = ''
    b1 = ''
    b2 = ''
    for c in cts:
        x = (c % p) % 2
        b += str(x)
    f = n2s(int(b,2))
    if verbose: print(f)
    if b'ASC' in f:
        print(f)


base = 2**255 + 2**127
for i in trange(2**24, 2**25-1): # 14066502
    if is_prime(base+i):
        primes.append(base+i)
        decrypt(base+i)

```

### Flag

```
ASCWG{DiV1n9_1n70_7h3_H0m0M0rpH1c_W0rl6_0f_We4k_Pr1m3_3nCryp7i0N}
```

### Notes

- https://github.com/coron/fhe
- https://eprint.iacr.org/2014/068.pdf
