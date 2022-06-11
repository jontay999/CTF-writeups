# Crypto - Permutation (452)

## Walkthrough

This was quite a fun challenge for me as I had no prior experience with any kind of permutation cryptosystems or symmetric groups before, I hit quite a few deadends and rabbit holes but I definitely learnt new things and enjoyed this challenge. Note: Full Source is at the bottom

We are given a Diffie-Hellman like cryptosystem but with permutation as the group operation. A generator is first created with a random permutation by

```python
arr = [i for i in range(n)]
random.shuffle(arr)

```

And then multiplying 2 elements in the group together would essentially be applying the permutation of the first element to the second element (simplified code)

```python
def multiply(elem1, elem2):
    res = []
    for i in elem1:
        res.append(elem2[i])
    return res
```

Note that these operations are commutative so the result of `elem1 * elem2 === elem2 * elem1`

We are then given the public keys of 'Alice' and 'Bob' (2 parties that are trying to communicate with this system) as well as the public key. The private keys are first generated with a large random 2048 bit number `a` and raising the generator to this exponent would be the public key `generator ^ a`. In Diffie Hellman, this would be the trapdoor function that would be easy to compute in the forward manner but hard to derive `a` given `generator ^ a`, essentially the discrete log problem. The exponentiation goes really fast in the square and multiply method (implementation in the source code).

In typical Diffie-Hellman, these public keys would be exchanged and a shared key can be derived from both parties using their private key. The implementation in this challenge is as follows

```python
#g is the generator
h = 2048
a = randbits(h); b = randbits(h)
A = g ** a; B = g ** b
S = A ** b # used as the key
```

`S` is the shared key, that both Alice and Bob, with access to their own private key are able to secretly compute using their own private keys. Alice would have access to Bob's public key and her own secret key and compute `B ^ a` and Bob would have access to Alice's public key and his own private key and compute `A ^ b`, which equate the shared key.

We are only given `A` and `B` and `g`, which means that the weakness must be something about the group. The solution to this problem can be done by finding out either `a` or `b` (both can be solved by the same method), but in this writeup I focus more on deriving `b` (following the code).

The first thing I tried to figure out was, what is the order of the group, or more specifically, the order of the element of the group, `g`. This means how many unique elements can be generated using the given generator `g`. To find that out I searched stuff like 'order of a permutation element', which led me to the idea of symmetric groups. Essentially the order of the group can be found by finding all the `k-cycles` of the group and taking their LCM which makes sense in a very intuitive way once I understood it.

For example given the first element of `g = [4848,653,2856...]`, the `k-cycle` of the first element would be how many positions do you have to traverse to before returning back to your original position. Perhaps its better illustrated with code.

```python
# To find out the length of k-cycle of the first element of g
idx = 0
elem = g[idx]
length = 1 #include the starting element
while elem != idx:
    elem = g[elem]
    length += 1
length += 1 #include the ending element
```

Now we just need to collect all the unique `k-cycle` lengths in order to compute the order of the generator element, or in more layman terms, what integer `k` in `g^(k-1)` will give the identity element, which in this case is `[0,1,2...,4999,5000]`. This makes sense because if it takes the first element `x` times to end up back in its starting place, then at `x-1` times it would be at its original index (before it shifts back to the starting position in the generator). If it takes the second element `y` times to end back in its starting place, then if the element is permuted `x * y` times, both the 1st and 2nd element will end up in their original places

```python
from math import lcm

cycle_lengths = set()
for i in range(len(g)):
    idx = i
    c = 1
    while g[g[idx]] != i:
        idx = g[idx]
        c += 1
    c += 1
    cycle_lengths.add(c)

order = lcm(*cycle_lengths) #2427239708460

# the spread operator '*' is great :)
```

Okay now we have the order of the group, but honestly that's where I got stuck. Actually there was no real need to compute the order of the group, but this formed the basis of my understanding of the final exploit.

What is needed next is to find out the order of the element `B` but with respect to the element `g`

```python
s = set()
for idx in range(len(g)):
    start = g[idx]
    target = B[idx]
    prev = None
    diff = None
    for i in range(order): # honestly a smaller number will do
        start = g[start]
        if start == target and prev == None:
            prev = i
        elif start == target:
            diff = i - prev
            break

    s.add((prev,diff))
```

What this code does is that it figures out two things

1. How long it takes from the `ith` element of `g` to end up in the `ith` position of `B`
2. How many times it will cycle around before ending back in the same position (this number repeats)

This then gives you a few equations that you can use to solve for `b`.

For every `(prev,diff)` pair, that is essentially a residue, modulo pair. Because to get from the `g[i]` element to the `B[i]` element the first time it takes `prev` number of multiplications, and in order to reach back again past the first time it will take `diff` more times. So we have many equations in the form

```
b = residue1 % mod1
b = residue2 % mod2
```

And we can solve that using the Chinese Remainder Theorem!

Now putting it all together

## Full Solution

```python
A = [...]
B = [...]
g = [...]
ct = bytes.fromhex('9f8a883d7e045010619a7aba5c0cdeb33ee0482626e2c5e718b3ef955ad9b4986d4406b6a1f53e78e506c7dcf806f964090a1e44fe2737b883')

pA = Perm(A)
pB = Perm(B)
pG = Perm(g)

s = set()
for idx in range(len(g)):
    start = g[idx]
    target = B[idx]
    prev = None
    diff = None
    for i in range(20000): # honestly any large number will do
        start = g[start]
        if start == target and prev == None:
            prev = i
        elif start == target:
            diff = i - prev
            break

    s.add((prev,diff))

res = [i[0] +2 for i in s] #need to add 2 here to include the starting and ending element
mod = [i[1] for i in s]

from sympy.ntheory.modular import crt
b = crt(mod, res)[0]
key = str(pA**b)

from hashlib import shake_256
def decrypt(key, ct):
    otp = shake_256(key.encode()).digest(len(ct))
    return xor(otp, ct)

def xor(a : bytes, b : bytes) -> bytes:
    return bytes([ x ^ y for x, y in zip(a, b)])


print(decrypt(str(key), ct))

```

## Flag

```
grey{DLP_Is_Not_Hard_In_Symmetric_group_nzDwH49jGbdJz5NU}
```

## Full Source (appendix)

```python
# perm.py
class Perm():
    def __init__(self, arr):
        assert self.valid(arr)
        self.internal = arr
        self.n = len(arr)

    def valid(self, arr):
        x = sorted(arr)
        n = len(arr)
        for i in range(n):
            if (x[i] != i):
                return False
        return True

    def __str__(self):
        return ",".join(map(str, self.internal))

    def __mul__(self, other):
        assert other.n == self.n
        res = []
        for i in other.internal:
            res.append(self.internal[i])
        return Perm(res)

    def __pow__(self, a):
        res = Perm([i for i in range(self.n)])
        g = Perm(self.internal)
        while (a > 0):
            if (a & 1): res = res * g
            g = g * g
            a //= 2
        return res
```

```python
# main.py
from secrets import randbits
from hashlib import shake_256
import random
import perm

FLAG = <REDACTED>

def encrypt(key : str) -> str:
    otp = shake_256(key.encode()).digest(len(FLAG))
    return xor(otp, FLAG).hex()

def xor(a : bytes, b : bytes) -> bytes:
    return bytes([ x ^ y for x, y in zip(a, b)])

n = 5000
h = 2048

arr = [i for i in range(n)]
random.shuffle(arr)

g = perm.Perm(arr)
a = randbits(h); b = randbits(h)
A = g ** a; B = g ** b
S = A ** b
key = str(S)

print(f"g = [{g}]"); print(f"A = [{A}]"); print(f"B = [{B}]");

print(f"c = {encrypt(key)}")
```
