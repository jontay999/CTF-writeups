# Cyber Santa – Common Mistake

- **Category:** Cryptography Day 1
- **Points:** 300
- **Difficulty:** ★☆☆☆

## Challenge

We were given just an `encrypted.txt` which had two dictionaries in the format

```
{n: RSA_modulus, e: RSA_exponent1, ct: encrypted_text1}
{n: RSA_modulus, e: RSA_exponent2, ct: encrypted_text2}
```

From the names of the keys in the dictionary. It was clear that this was an RSA encryption.

## Solution

Because both the modulus was the same, I suspected that there was probably a vulnerability relating to that. After some googling, I found a helpful article on Crypto StackExchange over [here](https://crypto.stackexchange.com/questions/16283/how-to-use-common-modulus-attack) detailing how the original ciphertext could be recovered with some clever math

For a more detailed writeup of how it works and the inner workings of RSA, I referred to [this article](https://infosecwriteups.com/rsa-attacks-common-modulus-7bdb34f331a5).

Given that the GCD of the 2 exponents was 1. I had to find 2 constants `s1` and `s2` such that

```
exponent1 x s1 + exponent2 x s2 = 1
```

Using [Bézout's Identity](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity), the two constants could be derived by

```
#euclidean's algo
def gcd(x, y):
    while(y):
        x,y = y, x%y
    return x

e1 = int(cipher1['e'], 16)
e2 = int(cipher2['e'], 16)

a = pow(e1,-1,e2)
b = int((gcd(e1,e2) - (a*e1))/e2)
```

Cipher Text 1 to the power of `a` and Cipher Text 2 to the power of `b` would yield the original plaintext because the GCD of the exponents was 1. (Note: the `pow()` function had to be used, otherwise the numbers would have been too big.)

```
from Crypto.Util.number import long_to_bytes
res = (pow(ct1, a, n) * pow(ct2,b, n)) %n
print(long_to_bytes(res))
```

The flag was

```
HTB{c0mm0n_m0d_4774ck_15_4n07h3r_cl4ss1c}
```

## Thoughts

- Learnt quite a lot about how RSA works and some finnicky Math identities
- Learnt that python actually has a strange limit on big numbers
- The `long_to_bytes` function from the `Crypto` library is really handy
