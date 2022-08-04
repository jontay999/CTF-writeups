## Crypto Challenge: Elliptic Clock Crypto

### Description/Source

```py
# Code inspired by https://ecchacks.cr.yp.to/clockcrypto.py

from random import seed, randrange
from hashlib import md5
from Crypto.Cipher import AES

from secret import FLAG

# 256-bit security!
p = 62471552838526783778491264313097878073079117790686615043492079411583156507853

class Fp:
    def __init__(self,x):
        self.int = x % p
    def __str__(self):
        return str(self.int)
    __repr__ = __str__
    def __int__(self):
        return self.int
    def __eq__(a,b):
        return a.int == b.int
    def __ne__(a,b):
        return a.int != b.int
    def __add__(a,b):
        return Fp(a.int + b.int)
    def __sub__(a,b):
        return Fp(a.int - b.int)
    def __mul__(a,b):
        return Fp(a.int * b.int)
    def __truediv__(a,b):
        return a*Fp(pow(b.int,-1,p))

class ClockPoint:
    def __init__(self,x,y):
        assert int(x*x + y*y) == 1
        self.x = x
        self.y = y
    def __str__(self):
        return f"({self.x},{self.y})"
    def __eq__(self, other):
        return str(self) == str(other)
    __repr__ = __str__
    def get_hash(self):
        return md5(str(self).encode()).digest()
    def __add__(self, other):
        x1,y1 = self.x, self.y
        x2,y2 = other.x, other.y
        return ClockPoint( x1*y2+y1*x2, y1*y2-x1*x2 )

def scalar_mult(x: ClockPoint, n: int) -> ClockPoint:
    y = ClockPoint(Fp(0),Fp(1))
    if n == 0: return y
    if n == 1: return x
    while n > 1:
        if n % 2 == 0:
            x = x + x
            n = n // 2
        else:
            y = x + y
            x = x + x
            n = (n-1) // 2
    return x + y


base_point = ClockPoint(Fp(34510208759284660042264570994647050969649037508662054358547659196695638877343),Fp(4603880836195915415499609181813839155074976164846557299963454168096659979337))

alice_secret = randrange(2**256)
alice_public = scalar_mult(base_point, alice_secret)
print("Alice's public key: ", alice_public)
bob_secret = randrange(2**256)
bob_public = scalar_mult(base_point, bob_secret)
print("Bob's public key: ", bob_public)

assert scalar_mult(bob_public, alice_secret) == scalar_mult(alice_public, bob_secret)
shared_secret = scalar_mult(bob_public, alice_secret)
key = shared_secret.get_hash()

print("Encrypted flag: ", AES.new(key, AES.MODE_ECB).encrypt(FLAG))

```

```
# output.txt
Alice's public key:  (929134947869102207395031929764558470992898835457519444223855594752208888786,6062966687214232450679564356947266828438789510002221469043877962705671155351)
Bob's public key:  (49232075403052702050387790782794967611571247026847692455242150234019745608330,46585435492967888378295263037933777203199027198295712697342810710712585850566)
Encrypted flag:  b' \xe9\x1aY.+E\xac\x1b\xc41\x1c\xf7\xba}\x80\x11\xa8;%]\x93\x88\x1fu\x87\x91\x88\x87\x88\x9b\x19'

```

We can verify that the $p-1$ is the order of the curve as it generates the identity point $(0,1)$, and is extremely smooth.

```py
p = 62471552838526783778491264313097878073079117790686615043492079411583156507853
print(scalar_mult(base_point, p-1))
# (0,1)

factors = [2,2 , 314075137 , 2003907193 , 2108232367 , 3119121991 , 4747407397 , 6439993607 , 8371785577 , 14743489193]
assert reduce(mul, factors) == p-1
```

Since the `ClockPoint` class maintains that

```py
assert int(x*x + y*y) == 1
```

We can see that the curve is actually a circle, and from this [paper](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.66.8688&rep=rep1&type=pdf), there is a proof that DLP within the circle group is equivalent to the problem of DLP within the underlying finite field.

### Solver

```python
ct  = b' \xe9\x1aY.+E\xac\x1b\xc41\x1c\xf7\xba}\x80\x11\xa8;%]\x93\x88\x1fu\x87\x91\x88\x87\x88\x9b\x19'
p = 62471552838526783778491264313097878073079117790686615043492079411583156507853
factors = [2,2 , 314075137 , 2003907193 , 2108232367 , 3119121991 , 4747407397 , 6439993607 , 8371785577 , 14743489193]
assert reduce(mul, factors) == p-1

ax, ay = (929134947869102207395031929764558470992898835457519444223855594752208888786,6062966687214232450679564356947266828438789510002221469043877962705671155351)
bx, by = (49232075403052702050387790782794967611571247026847692455242150234019745608330,46585435492967888378295263037933777203199027198295712697342810710712585850566)
gx, gy = (34510208759284660042264570994647050969649037508662054358547659196695638877343,4603880836195915415499609181813839155074976164846557299963454168096659979337)

alice_pub = ClockPoint(Fp(ax), Fp(ay))
blake_pub = ClockPoint(Fp(bx), Fp(by))
base_point = ClockPoint(Fp(int(gx)),Fp(int(gy)))


F = GF(p)
R.<w> = PolynomialRing(F)
K.<w> = F.extension(w^2 + 1) # its a circle!

generator = gx + gy*w
b_public = bx + by*w
b_secret = discrete_log(b_public, generator, p-1) # important to provide the order, otherwise it can't be solved

# added a cheeky eval(str()) otherwise the spacing will break the inequality
assert (bx,by) == eval(str(scalar_mult(base_point, b_secret)))

secret = scalar_mult(alice_pub, b_secret)
key = secret.get_hash()

flag = AES.new(key, AES.MODE_ECB).decrypt(ct)
print(flag)
```

### Flag

```
uiuctf{Circle5_ar3_n0t_ell1ptic}
```

### Notes

- [The True ECC, SEETF](https://juliapoo.github.io/ctf/2022/06/11/seetf2022-author-writeup.html#the-true-ecc)
- [Relevant Paper, page 5](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.66.8688&rep=rep1&type=pdf)
- https://imp.ress.me/blog/2022-08-01/uiuctf-2022/#elliptic-clock-crypto
- [Similar Question](https://blog.kelte.cc/ctf/writeup/2020/05/24/m0lecon-ctf-2020-teaser-king-exchange.html)
- [Why Circles suck](https://crypto.stackexchange.com/questions/11518/what-is-so-special-about-elliptic-curves)
