# niteCTF – Slow Passwords

- **Category:** Misc
- **Points:** 500

## Challenge

We are given an instance to connect to. We have to guess the correct password in order to be shown the flag. The password was 10 lower case letters and would be randomised each time a connection is established. We have 3 attempts to guess each character of the password, and each attempt took a suspicious amount of time to complete a result. The correct password is shown at the end if all tries have been exhausted

## Solution

1. After getting some very quick responses and some very long responses, it probably meant that the password characters somehow corresponded to the length of time it took to respond.
2. Upon more experimentation, every time I send in an `a` and the response was fast, the correct character was quite lexicographically close to `a` and vice versa.
3. The seconds it takes the server to respond directly correspond to the offset from the letter I sent in.
4. I crafted a script that would always send `a` as the first guess and time the amount of seconds it took to respond in order to decide the second guess.

```
from pwn import *
import random
from time import time

p = remote("slow-passwords.challenge.cryptonite.team", 1337)
print(p.recvlines(5))
curr = p.recvline()
print('start:',curr)
count = 0
while count < 11:
    curr = 'a'
    p.sendline(b'a')
    print(p.recvline())
    start = time()
    print(p.recvline())
    end = time()
    offset = round(end-start)
    print("offset:", offset)
    next = bytes(chr(ord('a')+offset), 'utf-8')
    p.sendline(next)
    print(p.recvline())
    print(p.recvline())
    count += 1

p.close()
```

And after leaving it to run a while, we get the flag.

```
niteCTF{Manipulating_time_is_easy} (something like that, will update later as I did not note the flag down)
```

## Thoughts

- Originally I thought there was a pattern to the passwords and calculated the difference between each character
- When that failed, I thought a random seed was initialized each time a connection was established and tried to match that pseudorandomness.
- Quite a unique challenge I must say hahaha
