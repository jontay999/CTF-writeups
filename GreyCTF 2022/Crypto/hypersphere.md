# Crypto - Hypersphere (489)

## Challenge Source

```python
# point.py
# Implementation of Quaternion in ring, such that all points have norm of 1

class Point():
    def __init__(self, a, b, c, d, p):
        assert (a * a + b * b + c * c + d * d) % p == 1
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.p = p

    def __str__(self):
        return f'{self.a}, {self.b}, {self.c}, {self.d}'

    def __mul__(self, other):
        assert self.p == other.p
        na = (self.a * other.a - self.b * other.b - self.c * other.c - self.d * other.d) % self.p
        nb = (self.a * other.b + self.b * other.a + self.c * other.d - self.d * other.c) % self.p
        nc = (self.a * other.c - self.b * other.d + self.c * other.a + self.d * other.b) % self.p
        nd = (self.a * other.d + self.b * other.c - self.c * other.b + self.d * other.a) % self.p
        return Point(na, nb, nc, nd, self.p)

    def __pow__(self, a):
        res = Point(1, 0, 0, 0, self.p)
        g = Point(self.a, self.b, self.c, self.d, self.p)
        while (a > 0):
            if (a & 1): res = res * g
            g = g * g
            a //= 2
        return res
```

```python
#main.py
from secrets import randbits
from hashlib import shake_256
from Crypto.Util.number import isPrime
import point

FLAG = <REDACTED>

p = 7489556970112255858194339343279932810383717284810081135153576286807813194468553481550905061983955290055856497097494238457954616159153509677256329469498187
ga = 2258050144523952547356167241343623076013743172411353499204671793264857719189919436799943033376317821578765115886815403845812363461384417662956951961353685
gb = 1069914179693951322883111467335954654818815798644770440034358650042824371401982086159904675631799159962201142170062814585463048527613494928890992373946863
gc = 11133097852046797355391346851525395533946845181651405581054631571635854160968086
gd = 7489556970112255858194339343279932810383717284810081135153576286807813194460592232877165912462810721221949401180338198644010019265640599992748426319034311

h = 512

g = point.Point(ga, gb, gc, gd, p)

def encrypt(msg : bytes, key : str) -> str:
    otp = shake_256(key.encode()).digest(len(msg))
    return xor(otp, msg).hex()

def xor(a : bytes, b : bytes) -> bytes:
    return bytes([ x ^ y for x, y in zip(a, b)])

def welcome():
    print('''
        _____
    ,-:` \;',`'-,
  .'-;_,;  ':-;_,'.
 /;   '/    ,  _`.-\\
| '`. (`     /` ` \`|
|:.  `\`-.   \_   / |
|     (   `,  .`\ ;'|
 \     | .'     `-'/
  `.   ;/        .'
jgs `'-._____.
    ''')
    print("Let's do Key Exchange using HyperSphere ヽ(o＾▽＾o)ノ\n", flush=True)

def checkPrime(prime : int) -> bool:
    return prime.bit_length() >= 512 and isPrime(prime)

def checkPoint(ta : int, tb : int, tc : int, td : int) -> bool:
    cond1 = 10 < ta < p - 2
    cond2 = 10 < tb < p - 2
    cond3 = 10 < tc < p - 2
    cond4 = 10 < td < p - 2
    cond5 = (ta * ta + tb * tb + tc * tc + td * td) % p == 1
    return cond1 and cond2 and cond3 and cond4 and cond5

def change():
    global p
    global g
    userIn = input("Do you wish to change the prime number and point? Y/N\n")
    if (userIn == "Y"):
        userPrime = int(input("New Prime: "))
        if (not checkPrime(userPrime)):
            print("Your prime is not suitable!")
            exit(0)
        p = userPrime

        userPoint = input("New Point (split by space): ").split()
        ta = int(userPoint[0])
        tb = int(userPoint[1])
        tc = int(userPoint[2])
        td = int(userPoint[3])
        if (not checkPoint(ta, tb, tc, td)):
            print("Your point is not suitable!")
            exit(0)
        g = point.Point(ta, tb, tc, td, p)


if __name__ == '__main__':
    welcome()
    print(f"Prime : {p}")
    print(f"Point : {g}")
    change()

    a = randbits(h); b = randbits(h)
    A = g ** a; B = g ** b
    S = A ** b
    key = str(S)
    msg = str(randbits(h)).encode()

    print(f"p = {p}"); print(f"g = ({g})"); print(f"A = ({A})"); print(f"B = ({B})");

    print(f"c = {encrypt(msg, key)}\n")

    ans = input("What's the msg?\n")
    if (ans.encode() == msg):
        print("Congratulations! Here's your flag (๑˃ᴗ˂)ﻭ")
        print(FLAG)
    else:
        print("You got it wrong... (＞ｍ＜) Try again!")

```

Its another key exchange problem, but this time involving Quaternions. I wasn't able to solve it during the CTF, and could only solve it after with the assistance of the author @mechfrog88 and @Neobeo.

We are able to choose the prime from which the Quaternion ring would be constructed, as well as any coordinates `(a,b,c,d)` that fulfil the condition that the norm is 1.

The solution involves picking a point with extremely small order, such that the private key `b` can be brute forced within that small order. For example, let's choose a target order of `3`

We then have to solve the equation where `(a,b,c,d)^3 == (1,0,0,0)` or the unit quaternion. There are infinitely many solutions for such a problem. A simple point to pick is `(-0.5, -0.5, -0.5, -0.5)`.

In order to ensure the point fits the criteria given of

```python
def checkPoint(ta : int, tb : int, tc : int, td : int) -> bool:
    cond1 = 10 < ta < p - 2
    cond2 = 10 < tb < p - 2
    cond3 = 10 < tc < p - 2
    cond4 = 10 < td < p - 2
    cond5 = (ta * ta + tb * tb + tc * tc + td * td) % p == 1
    return cond1 and cond2 and cond3 and cond4 and cond5
```

We can simply multiply these points by the inverse mod of `-2` with regard to the prime.

```python
ga = gb = gc = gd = pow(-2,-1,p)
```

(Note: I learnt during this challenge that python 3.8 onwards supports negative exponents so no more `from gmpy2 import invert` for me)

From there, we can begin interacting with the challenge and send off our points. With the returned `A` and `B`. We can retrieve the the private key `b` and extract the message

```python
for b in range(4):
    guess = g ** b
    if str(guess) == str(B):
        break

key = str(A ** b)

otp = shake_256(key.encode()).digest(h)
msg = xor(otp, bytes.fromhex(c))
```

And we're done! Here's the full solution below.

## Full Solution

```python
# nc challs.nusgreyhats.org 10521
from pwn import *
from point import Point
from hashlib import shake_256
from gmpy2 import next_prime
host, port = 'challs.nusgreyhats.org', 10521


def encrypt(msg : bytes, key : str) -> str:
    otp = shake_256(key.encode()).digest(len(msg))
    return xor(otp, msg).hex()

def xor(a : bytes, b : bytes) -> bytes:
    return bytes([ x ^ y for x, y in zip(a, b)])

h = 512

# any prime works!
pp = int(next_prime(2 << 512))

# find cube roots of unity here y solving (a,b,c,d)^3 == (1,0,0,0), many answers work

ga = gb = gc = gd = pow(-2,-1,pp) # all the points have absolute value -0.5
g = Point(ga, gb, gc, gd, pp)

# show that order of point is 3
test = g**4
assert (test.a, test.b, test.c, test.d) == (g.a, g.b, g.c, g.d)


p = remote(host, port)
p.sendlineafter(b'Y/N\n', b'Y')
p.sendline(str(pp).encode())
p.sendline(f'{ga} {gb} {gc} {gd}'.encode())


p.recvuntil(b'A = ')
A = eval(p.recvline().strip().decode('utf-8'))

p.recvuntil(b'B = ')
B = eval(p.recvline().strip().decode('utf-8'))

p.recvuntil(b'c = ')
c = p.recvline().strip().decode('utf-8')


A = Point(*A, pp)
B = Point(*B, pp)


for b in range(4):
    guess = g ** b
    if str(guess) == str(B):
        break

key = str(A ** b)

otp = shake_256(key.encode()).digest(h)
msg = xor(otp, bytes.fromhex(c))
print("Got msg:", msg)
p.sendline(msg)
p.interactive()

```

## Flag

```
grey{HyperSphereCanBeUsedForKeyExchangeToo!(JustProbablyNotThatSecure)_33JxCZjzQQ7dVGvT}
```

## Appendices

![author notes](../images/hypersphere.png)
