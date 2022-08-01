# TFC CTF 2022

## Crypto Challenge: Admin Panel but Harder and Fixed

Note: It was in fact still buggy/could be cheesed

### Description/Source

```py
import os
import random

from Crypto.Cipher import AES

KEY = os.urandom(16)
PASSWORD = os.urandom(16)
FLAG = os.getenv('FLAG')
# FLAG = "TESTING{FLAG}"

menu = """========================
1. Access Flag
2. Change Password
========================"""


def xor(bytes_first, bytes_second):
    d = b''
    for i in range(len(bytes_second)):
        d += bytes([bytes_first[i] ^ bytes_second[i]])
    return d


def decrypt(ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(KEY, AES.MODE_ECB)
    pt = b''
    state = iv
    for i in range(len(ct)):
        b = cipher.encrypt(state)[0]
        c = b ^ ct[i]
        pt += bytes([c])
        state = state[1:] + bytes([ct[i]])
    return pt


if __name__ == "__main__":
    while True:
        print(menu)
        option = int(input("> "))
        if option == 1:
            password = bytes.fromhex(input("Password > "))
            if password == PASSWORD:
                print(FLAG)
                exit(0)
            else:
                print("Wrong password!")
                continue
        elif option == 2:
            token = input("Token > ").strip()
            if len(token) != 64:
                print("Wrong length!")
                continue
            hex_token = bytes.fromhex(token)
            r_bytes = random.randbytes(32)
            print(f"XORing with: {r_bytes.hex()}")
            xorred = xor(r_bytes, hex_token)
            PASSWORD = decrypt(xorred)
```

The objective of this is to predict what the value of `PASSWORD` is, and we will be able to get the flag. We are allowed to give 32 bytes as a token that are xorred with randomly generated 32 bytes. The result of this operation will be passed to the `decrypt` function and the result is assigned to `PASSWORD`.

The only information we receive are the 32 random bytes generated, which gives a hint that this is the key to solving the question. Originally, I thought you can force the `decrypt` into some oracle if you can trigger some error, but there wasn't any `try except` so even if an error could be triggered, it would just end the challenge there.

The key is that `random.randbytes(32)` is vulnerable to RNG prediction. This can be tested out by looking at the results of

```py
import random
from libnum import n2s
random.seed(0)
test1 = ' '.join([n2s(random.getrandbits(32)).hex() for _ in range(8)])
random.seed(0)
test2 = random.randbytes(32).hex()
test2 = ' '.join([test2[i:i+8] for i in range(0,len(test2), 8)])
print(f"Test 1: {test1}")
print(f"Test 2: {test2}")

# Test 1: d82c07cd 629f6fbe c2094cac e3e70682 6baa9455 0a5d2f34 42485e3a f728b4fa
# Test 2: cd072cd8 be6f9f62 ac4c09c2 8206e7e3 5594aa6b 342f5d0a 3a5e4842 fab428f7
```

Typical RNG predictors require that you pass in 32 bit numbers, but `randbytes(32)` will return a 256 bit number. However you can transform it into 8 32 bit numbers by splitting them apart and changing the endianness.

Then by making $624 / 8 $ queries, we are able to predict the value of the next `random.randbytes(32)`. We can then send that as our token, which will cause the xorred token value to be a bunch of `0`s.

However we still don't know the value of `KEY` which is never leaked

```py
KEY = os.urandom(16)
```

But if we pass `b'\x00'*32` into the `decrypt` function, it will come out all the 16 bytes of repeated characters, so we can just guess all the 256 possibilities.

### Solver

```python
# nc 01.linux.challenges.ctf.thefewchosen.com 50682

from pwn import *
from libnum import *
from mt19937predictor import MT19937Predictor
from tqdm import trange
from Crypto.Cipher import AES
host, port = "01.linux.challenges.ctf.thefewchosen.com", 53505



def local():
    predictor = MT19937Predictor()
    KEY = b'a'*16

    def xor(bytes_first, bytes_second):
        d = b''
        for i in range(len(bytes_second)):
            d += bytes([bytes_first[i] ^ bytes_second[i]])
        return d

    def decrypt(ciphertext):
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(KEY, AES.MODE_ECB)
        pt = b''
        state = iv
        for i in range(len(ct)):
            b = cipher.encrypt(state)[0]
            c = b ^ ct[i]
            pt += bytes([c])
            state = state[1:] + bytes([ct[i]])
        return pt
    random.seed(0)
    rs = [random.randbytes(32).hex() for _ in range(624//8)]
    cs = 0
    for res in rs:
        res = bytes.fromhex(res)
        res = [s2n(res[i:i+4][::-1]) for i in range(0,len(res),4)]
        for i in res:
            cs += 1
            predictor.setrandbits(i,32)
    print("Total count:", cs)
    predicted = [predictor.getrandbits(32) for i in range(8)]
    predicted = b''.join([n2s(i)[::-1] for i in predicted])

    r_bytes = random.randbytes(32)
    print(r_bytes)
    print(predicted)
    assert r_bytes == predicted

    hex_token = predicted.hex()
    xorred = xor(bytes.fromhex(r_bytes.hex()), bytes.fromhex(hex_token))
    PASSWORD = decrypt(xorred)
    print(PASSWORD)
    breakpoint()


def solve():
    predictor = MT19937Predictor()
    p = remote(host, port)
    count = 0
    for _ in range(624//8):
        print("Count;", count)
        if count == 624: break
        p.sendline(b'2')
        p.sendlineafter(b'Token > ', b'a'*64)
        p.recvuntil(b'XORing with: ')
        res = p.recvline().strip().decode('utf-8')
        res = bytes.fromhex(res)
        res = [s2n(res[i:i+4][::-1]) for i in range(0,len(res),4)]

        for i in res:
            count += 1
            predictor.setrandbits(i, 32)

    print("Count:", count)
    predicted = [predictor.getrandbits(32) for i in range(8)]
    predicted = b''.join([n2s(i)[::-1] for i in predicted])
    print("Predicted:", predicted)
    p.sendline(b'2')
    p.sendlineafter(b'Token > ', predicted.hex().encode())


    for i in trange(256):
        pw = (bytes([i]).hex())*16
        p.sendline(b'1')
        p.sendlineafter(b'Password > ', pw.encode())
        line = p.recvline()
        if b'Wrong pass' not in line:
            print(line)
            p.interactive()


    breakpoint()

# local()
solve()
```

### Flag

```

```

### Extra

Note that the challenge could be solved by passing `b'00' + ' '*60 + b'00'` as the token, this will cause `bytes.fromhex(token)` to read it as `b'\x00\x00'`. The xorred value will only be 2 bytes long as well, so in the `decrypt` function,

```py
iv = ciphertext[:16]
ct = ciphertext[16:]
```

There is no `ct` so the password comes out as an empty string, so giving an empty string for password will leak the flag.
