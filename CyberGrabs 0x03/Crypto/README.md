# CyberGrabs 0x03 2022 – Crypto Challenges

## Challenge 1: RSA

We are given 3 moduli and 3 cipher texts. Finding the prime factors is just a matter of finding the gcd and decrypting RSA in a standard fashion.

```
n1 (n1 = p*q)
n2 (n2 = q*r)
n3 (n3 = r*p)

c1 , c2, c3
```

### Solution

Exploit Solution

```
q = gcd(n1,n2)
r = gcd(n2,n3)
p = gcd(n1,n3)
assert p*q == n1
assert r*q == n2
assert p*r == n3

e = 65537

def decrypt(p1,p2,ct,exponent):
    phi = (p1-1)*(p2-1)
    n = p1*p2
    divisor, d, b = egcd(exponent, phi)
    pt = pow(ct,d,n)
    return n2s(pt)

print(decrypt(p,q,c1,e) + decrypt(r,q,c2,e) + decrypt(p,r,c3,e))
```

### Flag

```
Flag{Bas!c_R5A_but_wi7H_extra_SpIc3}
```

## Challenge 2: #031337

A pdf of an image with some bright colors was shown

![031337](./images/1.png)

### Solution

Searching cipher encoding with colored squares led me to hexahue encoding. Using dcode's hexahue decoder we get the flag

![31337 answer](./images/2.png)

### Flag

```
cybergrabs{IT5_H3X4HU3_ENCODIN9}
```

## Challenge 3: t0ti3nt

We are given the source encrypting file and the output text

```
from sympy import totient

flag = REDACTED

def functor(n):
    val = 0
    for j in tqdm(range(1,n+1)):
        for i in range(1,j+1):
            val += j//i * totient(i)
    return val

lest = []
for i in flag:
    lest.append(functor(ord(i)*6969696969))

print(lest)
```

### Solution

The numbers were too slow and big to rerun the script so I wanted to find a pattern

Running the numbers 1 to 100, it showed that the difference in successive numbers increased by one which indicated triangular numbers. More research showed that it was just a binomial coefficient of (i+1) and 3 for the ith number.

```
def testing():
    prev = 0
    for i in range(100):
        res = functor(i)
        check = scipy.special.comb(i+2,3,exact=True)
        print(f"{i}: {res}, Diff: {res-prev}, Check: {check}")
        prev = res
```

The solution was then to just do a mapping using the resultant values of ascii numbers and the resultant binomial coefficient numbers.

```
def getFlag():
    flag = ""
    multiplier = 6969696969
    d = {}
    for i in range(128):
        d[scipy.special.comb((i*multiplier+2),3,exact=True)] = chr(i)
    for i in output:
        flag += d[i]
    print(flag)
```

### Flag

```
cybergrabs{50m3_func710nS_n3v3r_c3A5e_t0_4m4z3_m3}
```

## Challenge 4: asrysae (50 points)

We are given encrypting script and the output text.

```
p = getPrime(512)
q = getPrime(512)
e = 65537

m = bytes_to_long(flag)

ciphertext = pow(m, e, p*q)

ciphertext = long_to_bytes(ciphertext)
obj1 = open("ciphertext.txt",'w')
obj1.write(f"p={p}\n\n")
obj1.write(f"q={q}\n\n")
obj1.write(f"ct={ciphertext.hex()}")
```

### Solution

It was just a very basic RSA decryption because all the values were there already.

```
from libnum import n2s
def decrypt(p1,p2,ct,exponent):
    phi = (p1-1)*(p2-1)
    n = p1*p2
    divisor, d, b = egcd(exponent, phi)
    pt = pow(ct,d,n)
    return n2s(pt)
e = 65537
print(decrypt(p,q,ct,e))
```

### Flag

```
cybergrabs{N0w_eVEN_RS4_i5_HAcKA81e}
```

## Challenge 5: Unbr34k4bl3

### Disclaimer: I did not manage to solve this during the challenge
