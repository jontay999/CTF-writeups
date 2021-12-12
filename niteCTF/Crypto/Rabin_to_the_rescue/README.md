# niteCTF – Rabin to the Rescue

- **Category:** Crypto
- **Points:** 500

## Challenge

We are given a server instance to connect to and the encrypting script `rabin_to_the_rescue.py`. Connecting to the server, we can get the flag's encrypted hexadecimal form, and we can also send a plaintext to be encrypted with the same keys as the flag.

## Solution

1. The title of the challenge implies the use of Rabin Cryptosystem which is about the same as RSA.
2. The vulnerability is in how the 2 primes are generated. As the primes are consecutive primes, it means that the two primes `p` and `q` can be approximately derived from the square root of the modulus `n`
3. I got some script from a similar [challenge](https://ctftime.org/writeup/13741) that was able to approximate the square root and get the exact primes afterwards

```
appr = int(n**0.5)
digit = 77 #this has to be hardcoded, the number of digits in modulus //2

while digit > -1:
    for i in range(11):
        if ((appr + i * 10 ** digit)**2 - n) > 0:
            appr = appr + (i-1) * 10 **digit
            digit = digit - 1
            print(appr)
            break

for i in range(1000):
    if n % (appr + i) == 0:
        print(appr + i)
```

4. With these 2 numbers, I follow the [article](https://en.wikipedia.org/wiki/Rabin_cryptosystem#Computing_square_roots) on Wikipedia detailing the decryption steps. (Which involves math I don't understand, extended Euclid algorithm to find GCD, Chinese Remainder Theorem to get possible cipehr texts)

Using similar scripts to the CTFTime writeup I referenced above, I got the flag

```
nite{r3p34t3d_r461n_3ncrypt10n_l1tr4lly_k1ll5_3d6f4adc5e}
```

## Thoughts

- Quite smart way of approximating and identifying prime numbers from a large modulus
