# Crypto - Lorge (433) - 29 solves

## Challenge

```python
#!/usr/bin/env python3

import string
import random

config = [[int(a) for a in n.strip()] for n in open("jbox.txt").readlines()] # sbox pbox jack in the box

# secure hashing algorithm 42
def sha42(s: bytes, rounds=42):
  out = [0]*21
  for round in range(rounds):
    for c in range(len(s)):
      if config[((c//21)+round)%len(config)][c%21] == 1:
        out[(c+round)%21] ^= s[c]
  return bytes(out).hex()

def main():
  print("Can you guess my passwords?")
  for trial in range(50):
    print(f"--------ROUND {trial}--------")
    password = "".join([random.choice(string.printable) for _ in range(random.randint(15,20))]).encode()
    hash = sha42(password)
    print(f"sha42(password) = {hash}")
    guess = bytes.fromhex(input("hex(password) = ").strip())
    if sha42(guess) == hash:
      print("Correct!")
    else:
      print("Incorrect. Try again next time.")
      exit(-1)
  flag = open("flag.txt", "r").read()
  print(f"Congrats! Your flag is: {flag}")

if __name__ == "__main__":
  main()
```

- Notice that the hashing is just a bunch of xor relations, with that everything can be reduced to `z3` constraints
- For every hash that comes in, brute force all lengths --> collect the relations --> check satisfiability
- For some reason, some of the solutions did not have satisfiable equations if I limited it to printable characters so I had to expand the range

```
# z.add(i >=33, i <= 126) # doesn't find me some of the answers
z.add(i>=0, i <= 126)
```

- Some of the solutions I found only appeared for higher lengths like 26 or 27 but they seemed to churn it out quickly enough so that's alright for me
- Just leave it on a while loop so if any part fails, it will just try again

## Full Solution

```python
from functools import reduce

from pwn import *
from z3 import *

host, port = "hash.chal.imaginaryctf.org" ,1337
config = [[int(a) for a in n.strip()] for n in open("jbox.txt").readlines()] # sbox pbox jack in the box

def returnOut(length):
    rounds = 42
    out = [set() for i in range(21)]
    for round in range(rounds):
        for c in range(length):
            if config[((c//21)+round)%len(config)][c%21] == 1:
                if c in out[(c+round)%21]:
                    out[(c+round)%21].remove(c)
                else:
                    out[(c+round)%21].add(c)
    return out

def derive(length, target):
    z = Solver()
    f = [BitVec('f{:02}'.format(i), 32) for i in range(length)]
    for i in f:
        # z.add(i >=33, i <= 126)
        z.add(i>=0, i <= 126)
    out = returnOut(length)
    for i in range(len(out)):
        z.add(reduce(lambda x,y: x ^ f[y], out[i], 0) == target[i])
    while z.check() == sat:
        password = (''.join(chr(z.model()[i].as_long()) for i in f))
        return password
    else:
        pass
    return False

# nc hash.chal.imaginaryctf.org 1337
def solve():
    p = remote(host, port)
    limit = 32
    for _ in range(50):
        print("Round:", _)

        p.recvuntil(b'sha42(password) = ')
        line = (p.recvline().strip())
        print(line)
        hash = line.decode('utf-8')
        target = bytes.fromhex(hash)
        for i in range(10,limit):
            res = derive(i, target)
            if res:
                p.sendline(res.encode().hex().encode())
                print(p.recvline(), i)
                if (i > 26):
                    print(i)
                if _ == 49: p.interactive()
                break
        if i == limit-1:
            print("Something wong")
            p.close()
            return
    p.close()

while(True):
    solve()

```

## Flag

```
ictf{pls_d0nt_r0ll_y0ur_0wn_hashes_109b14d1}
```

### Other solutions

1. @f4tu

```py
#!/usr/bin/env python3
from pwn import *
import string
import random

r = remote("hash.chal.imaginaryctf.org", 1337)

config = [[int(a) for a in n.strip()] for n in open("jbox.txt").readlines()] # sbox pbox jack in the box
def sha42(s: bytes, rounds=42):
    out = [0]*21
    for round in range(rounds):
        for c in range(len(s)):
            if config[round % len(config)][c % 21] == 1:
                out[(c+round)%21] ^= s[c]
    return bytes(out)
for i in range(50):
    print(r.recvuntil(b'sha42(password) = '))
    String = bytes.fromhex((r.recvline()).decode())
    for _ in range(95045):
        String = sha42(String)
    r.recvuntil(b'hex(password) = ')
    r.sendline((String.hex()).encode())
```

- apparently it was cyclic lol
