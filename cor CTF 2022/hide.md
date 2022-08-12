## Crypto Challenge: hidE

### Description/Source

```python
#!/usr/local/bin/python
import random
import time
import math
import binascii
from Crypto.Util.number import *

p, q = getPrime(512), getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)

flag = open('./flag.txt').read().encode()

random.seed(int(time.time()))

def encrypt(msg):
    e = random.randint(1, n)
    while math.gcd(e, phi) != 1:
        e = random.randint(1, n)
    pt = bytes_to_long(msg)
    ct = pow(pt, e, n)
    return binascii.hexlify(long_to_bytes(ct)).decode()


def main():
    print('Secure Encryption Service')
    print('Your modulus is:', n)
    while True:
        print('Options')
        print('-------')
        print('(1) Encrypt flag')
        print('(2) Encrypt message')
        print('(3) Quit')
        x = input('Choose an option: ')
        if x not in '123':
            print('Unrecognized option.')
            exit()
        elif x == '1':
            print('Here is your encrypted flag:', encrypt(flag))
        elif x == '2':
            msg = input('Enter your message in hex: ')
            print('Here is your encrypted message:', encrypt(binascii.unhexlify(msg)))
        elif x == '3':
            print('Bye')
            exit()

if __name__ == '__main__':
    main()

```

We are given an encryption oracles that encrypts the flag or a plain text of our choice, using random exponents seeded by time. We can send in a known plaintext in order to figure out the seed used.

Next because we have a common modulus, we can just use the common modulus attack in order to figure out the flag, as long as the exponents are coprime.

Some exponents generated from the seed will be discarded if they are not coprime to phi, but we can just brute force a bit. To make things a bit more reliable, after getting an encryption of the flag, we can see what possible exponents were used by checking what `e` was used for the encryption of the plaintext.

### Solver

```py
# nc be.ax 31124
from pwn import *
from libnum import *
import random
import time
from math import gcd
from itertools import product, permutations
from tqdm import *


def solve():

    test_pt = 3
    host, port = 'be.ax', 31124
    p = remote(host, port)
    seed = int(time.time())

    p.recvuntil(b'Your modulus is: ')
    n = eval(p.recvline().strip().decode('utf-8'))
    print("Mod:", n)

    def attack(c1, c2, e1, e2, N):
        if gcd(e1, e2) != 1:
            # raise ValueError("Exponents e1 and e2 must be coprime")
            return False
        a = pow(e1,-1,e2)
        b = int((gcd(e1,e2) - (a*e1))//e2)
        res = n2s((pow(c1, a, N) * pow(c2,b, N)) % N)
        if b'corctf' in res:
            print(res)
            return True
        return False


    def getFlag():
        p.sendline(b'1')
        p.recvuntil(b'Here is your encrypted flag: ')
        flag = s2n(bytes.fromhex(p.recvline().strip().decode('utf-8')))
        assert flag < n
        return flag

    def getEncryption(m):
        m = n2s(m).hex()
        p.sendline(b'2')
        p.sendline(m.encode())
        p.recvuntil(b'Here is your encrypted message:')
        ct = s2n(bytes.fromhex(p.recvline().strip().decode('utf-8')))
        return ct

    def getSeed():
        test = getEncryption(test_pt)
        for i in range(seed-5, seed+5):
            random.seed(i)
            count = 0
            while True:
                count += 1
                test_e = random.randint(1,n)
                test_out = pow(test_pt, test_e, n)
                if test_out == test:
                    print("Took:", count)
                    print("Seed:", i)
                    return i, test_e
                if count > 30:
                    break

    def getExponents():
        possible_exp = []
        count = 0
        c = getEncryption(test_pt)
        e = 0
        while pow(test_pt, e, n) != c:
            count += 1
            e = random.randint(1,n)
            possible_exp.append(e)
            if count > 2000:
                print("Something went wrong, weird exponent")
                raise Exception

        return possible_exp

    seed, encrypted_e = getSeed()
    random.seed(seed)
    while True:
        test = random.randint(1,n)
        if test == encrypted_e:
            break

    def legit():
        all_cts = []
        all_exps = []
        tries = 5
        for i in range(tries):
            ct = getFlag()
            all_cts.append(ct)
            exps = getExponents()
            print(f"Try {i+1} {len(exps)} Exponents:")
            all_exps.append(exps)

        for i in trange(tries):
            for j in range(i, tries):
                c1, c2 = all_cts[i], all_cts[j]
                for e1,e2 in product(all_exps[i], all_exps[j]):
                    if gcd(e1,e2) == 1 and attack(c1,c2,e1,e2,n):
                        exit()
        print("Failed :(")
    while True:
        legit()

    p.close()

solve()

```

### Flag

```
corctf{y34h_th4t_w4snt_v3ry_h1dd3n_tbh_l0l}
```

### Notes

- Don't overcomplicate things, remember the basics (I didn't even consider common modulus attack until a teammate pointed it out)
- Remember that `/ != //`
