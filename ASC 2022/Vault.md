## Crypto Challenge: Vault

### Description/Source

```py
from Crypto.Util.number import (
    getPrime,
    getRandomRange,
    getRandomNBitInteger,
    long_to_bytes,
    inverse,
)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from hashlib import sha1

Point = namedtuple("Point", "x y")
O = Point(0, 1)

class ECC:
    def __init__(self, BITS=128) -> None:
        assert BITS >= 128
        self.p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
        self.a = -32
        self.b = 7
        self._private = getRandomNBitInteger(BITS) % self.p

    def encrypt(self, P: Point, message):
        C = self.mul(P, self._private)
        key = sha1(long_to_bytes(C.x * self.inv_mod_p(C.y) % self.p)).digest()[:16]
        cipher = AES.new(key, AES.MODE_CBC)
        print(key.hex())
        return key.hex(), cipher.iv.hex(), cipher.encrypt(pad(message, 16)).hex()

    def add(self, P: Point, Q: Point) -> Point:
        # Adding 2 Points P and Q on the curve

        if not (self.valid(P) and self.valid(Q)):
            raise ValueError("Invalid points")

        if P == O:
            return Q
        if Q == O:
            return P
        if P.x == Q.x and P.y == -Q.y % self.p:
            return O
        else:
            if P == Q:
                y_diff = (3 * (P.x**2) + self.a) % self.p
                x_diff = (2 * P.y) % self.p

            else:
                y_diff = (Q.y - P.y) % self.p
                x_diff = (Q.x - P.x) % self.p

            slope = (y_diff * self.inv_mod_p(x_diff)) % self.p
            x3 = (slope**2 - P.x - Q.x) % self.p
            y3 = (slope * (P.x - x3) - P.y) % self.p
            return Point(x3, y3)

    def inv_mod_p(self, x):
        if x % self.p == 0:
            raise ZeroDivisionError("Impossible inverse")
        return pow(x, self.p - 2, self.p)

    def valid(self, P) -> bool:
        if P == O:
            return True
        return (
            (P.y ** 2 - (P.x ** 3 + self.a * P.x + self.b)) % self.p == 0
            and 0 <= P.x < self.p
            and 0 <= P.y < self.p
        )

    def mul(self, P: Point, n: int) -> Point:
        # Adding a Point P to itself n times
        Q = P
        R = O
        while n:
            if n & 1:
                R = self.add(Q, R)
            Q = self.add(Q, Q)
            n >>= 1
        return R

ecc = ECC()
G = Point(39613264652991136516316121365481995043381995333181795575614979310610916877953, 14487697298980196960516056623210206756245610286316104440426923097340932458937)

with open("vault.json", "rb") as h1, open("vault.enc", "wb") as h2:
    vault = h1.read()
    key, iv, enc = ecc.encrypt(G,vault)
    h2.write(bytes.fromhex(enc))
```

We are given the parameters of an ECC curve and we are supposed to derive the private key that is multiplied by the generator in order to determine the key used for AES encryption.

Note that this is CBC mode of encryption, so even though we don't have the IV, this just means that we are unable to decrypt the first 16 bytes, but the remainder of the message can be decrypted.

There doesn't seem to be obvious vulnerabilities in the ECC encryption, so we should look at the generator given

```py
p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
a = -32
b = 7

E = EllipticCurve(Zmod(p), [a, b])
order = E.order() #115792089237316195423570985008687907853264940319343637670799236344821017363221

gx, gy = (39613264652991136516316121365481995043381995333181795575614979310610916877953, 14487697298980196960516056623210206756245610286316104440426923097340932458937)

g = E(gx, gy)
g_ord = g.order() # 12708491 (suspicious!!)
```

Even though the order of the curve is large, the order of the point itself is only 8 digits which means its brute-forceable. I prefer to use sage's implementation which is a bit faster, but basically the idea, is to keep guessing the private key (which has to be within the order) and see if it decrypts to anything meaningful. The flag is gotten after ~40 mins but in the worst case scenario it would take about 2-3 hours.

### Solver

```python
p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
a = -32
b = 7

E = EllipticCurve(Zmod(p), [a, b])
order = E.order() #115792089237316195423570985008687907853264940319343637670799236344821017363221

gx, gy = (39613264652991136516316121365481995043381995333181795575614979310610916877953, 14487697298980196960516056623210206756245610286316104440426923097340932458937)

g = E(gx, gy)
g_ord = g.order() # 12708491 (suspicious!!)


from tqdm import *
from Crypto.Util.number import (
    getPrime,
    getRandomRange,
    getRandomNBitInteger,
    long_to_bytes,
    inverse,
)
from Crypto.Cipher import AES
from hashlib import sha1


with open('./player/vault.enc', 'rb') as f:
    ct = f.read()

for i in trange(12708491, -1, -1):
    x, y, _ = g*i
    inv = pow(y, p-2,p)
    key = sha1(long_to_bytes(int(int(x * inv) % p))).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC)
    flag = cipher.decrypt(ct)
    if b'ASCWG' in flag:
        print(flag)
        break

# 2525730 is the private key

```

### Flag

```
ASCWG{Curv3_0u7_7h3_3111pt1c_5m4l1_0rd3r_0f_8i7c0in_$3cp256k1}

b'\xdf\x01\xacH\xc1\x00\x18L\x1e\xb6"\xbf~\xa6\x15\xf0  "email": "s3c@ascwg.com",\r\n        "password": "n0th1ng1mp0rt4nt"\r\n    },\r\n    {\r\n        "email": "y4mm1@ascwg.com",\r\n        "password": "ASCWG{Curv3_0u7_7h3_3111pt1c_5m4l1_0rd3r_0f_8i7c0in_$3cp256k1}"\r\n    },\r\n    {\r\n        "email": "4dm1n@ascwg.com",\r\n        "password": "4dm1n4lw4ysh3re123"\r\n    },\r\n    {\r\n        "email": "h04x@ascwg.com",\r\n        "password": "0ne7w0thr33h04x"\r\n    }\r\n]\r\n\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```

### Notes
