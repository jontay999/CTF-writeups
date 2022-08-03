# VSCTF 2022 – Crypto Challenge

## Art Final (35 solves): 478 points

### Description/Source

```python
# Teacher, please give me an A
import random
from PIL import Image


boring = Image.open('Art_Final_2022.png', 'r').convert('RGBA')
boring_pix = boring.load()

spicy = Image.new('RGBA', boring.size)
spicy_pix = spicy.load()

# Add SPICE
for i in range(boring.size[0] * boring.size[1]):
    x = i % boring.size[0]
    y = i // boring.size[0]
    rgba = tuple(random.randbytes(4))
    spicy_pix[x, y] = tuple([bore ^ spice for bore, spice in zip(boring_pix[x, y], rgba)])

# This final is HOT
spicy.save('ENHANCED_Final_2022.png')


# oh shoot, i forgot there needs to be a flag ._.
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode

key = bytes(random.sample(random.randbytes(16), 16))
iv = Random.new().read(AES.block_size)
enc = AES.new(key, AES.MODE_CBC, iv)
flag = b64encode(iv + enc.encrypt(pad(b'[REDACTED]', AES.block_size))).decode()

print(flag)  # Tl5nK8L2KYZRCJCqLF7TbgKLgy1vIkH+KIAJv5/ILFoC+llemcmoLmCQYkiOrJ/orOOV+lwX+cVh+pwE5mtx6w==

```

We have 2 images which have each pixel mangled by `random.randbytes(4)` with the xor operation. We can recover each of these randomly generated bytes as we have both the original and mangled image.

Looking at the [source](https://github.com/python/cpython/blob/v3.9.0/Lib/random.py), we can find that the method for generating `randbytes(4)` is equivalent to `random.getrandbits(32)`, so we can recover the full Mersenne twister state with just 624 values. It is important to note that `randbytes(4)` generates it back to front so we have to remember to reverse it.

```python
def randbytes(self, n):
    """Generate n random bytes."""
    return self.getrandbits(n * 8).to_bytes(n, 'little')
```

From there, we can just re-implement the `random.sample` method using the predictor we have. (Thanks to @Angmar for this part, cos I was lazy haha) and decode the flag.

### Solver

```python
from PIL import Image
from base64 import b64decode
from Crypto.Cipher import AES
from randcrack import RandCrack
from libnum import s2n,n2s
import random
from tqdm import tqdm
from mt19937predictor import MT19937Predictor

#rccrack and mt19937predictor both function sufficiently well

i1 = Image.open('Art_Final_2022.png', 'r').convert('RGBA')
i1_pic = i1.load()

i2 = Image.open('ENHANCED_Final_2022.png', 'r').convert('RGBA')
i2_pic = i2.load()

states = []
for i in range(i1.size[0] * i1.size[1]):
    x = i % i1.size[0]
    y = i // i1.size[0]

    p1 = i1_pic[x, y]
    p2 = i2_pic[x, y]

    arr = []
    for i in range(3,-1,-1):
        p = p1[i] ^ p2[i]
        arr.append(p)
    states.append(s2n(bytes(arr)))

predictor = MT19937Predictor()
rc = RandCrack()

states = states[-624:]

for i in range(624):
    predictor.setrandbits(states[i], 32)
    rc.submit(states[i])


key = n2s(predictor.getrandbits(16*8))[::-1]

print('starting random sample')
def _randbelow_with_getrandbits(n):
    "Return a random int in the range [0,n).  Returns 0 if n==0."

    if not n:
        return 0
    k = n.bit_length()  # don't use (n-1) here because n can be 1
    r = predictor.getrandbits(k)  # 0 <= r < 2**k
    while r >= n:
        r = predictor.getrandbits(k)
    return r

from math import log as _log, exp as _exp, pi as _pi, e as _e, ceil as _ceil

def randomSample(population, k):
    n = len(population)
    result = [None] * k
    setsize = 21        # size of a small set minus size of an empty list
    if k > 5:
        setsize += 4 ** _ceil(_log(k * 3, 4))  # table size for big sets
    if n <= setsize:
        # An n-length list is smaller than a k-length set.
        # Invariant:  non-selected at pool[0 : n-i]
        pool = list(population)
        for i in range(k):
            j = _randbelow_with_getrandbits(n - i)
            result[i] = pool[j]
            pool[j] = pool[n - i - 1]  # move non-selected item into vacancy
    return bytes(result)

key = randomSample(key, 16)
ct = b"Tl5nK8L2KYZRCJCqLF7TbgKLgy1vIkH+KIAJv5/ILFoC+llemcmoLmCQYkiOrJ/orOOV+lwX+cVh+pwE5mtx6w=="
ct = b64decode(ct)
iv = ct[:AES.block_size]
ct = ct[AES.block_size:]
enc = AES.new(key, AES.MODE_CBC, iv)
pt = enc.decrypt(ct)
print(pt)
```

### Flag

```
vsctf{1_gu355_R4ND0m_i5nt_tH4T_5p1cy}
```

### Notes

The solve is actually not that interesting, but I wanted to try to use this to try to explore other modes of random cracking.

The standard one to use is the [Mersenne Twister Predictor](https://github.com/kmyk/mersenne-twister-predictor)

However, I was wondering whether the same challenge could be solved if the randomness was generated 1 byte at a time, rather than the convenient 4 bytes. Because most challenges and most tools require the `getrandbits(32)` to predict correctly.

```python
import random
from mt19937predictor import MT19937Predictor
from libnum import n2s, s2n
predictor = MT19937Predictor()
states = [random.randbytes(1) for _ in range(1000*4)]
states = [s2n(b''.join(states[i:i+4])) for i in range(0,len(states),4)]
states_test = [s2n(random.randbytes(4)[::-1]) for _ in range(1000)]

def test(states, num=624):
    predictor = MT19937Predictor()
    for i in range(num):
        predictor.setrandbits(states_test[i], 32)
    for i in range(num, len(states)):
        assert states[i] == predictor.getrandbits(32)
    print("works")

test(states_test)
test(states)
```

It seems that if it generates 1 byte at a time, it can't predict it well at all.

I managed to find a [repo](https://github.com/fx5/not_random/tree/3287b1f5c965672ef7f1a97ab00b16b5e64a5f0a) that can recover the state using 1-7 bits of output (albeit with a larger source), but it seems to only work for python2, hopefully will be able to update this soon with an answer

#### Relevant Links

- Python `random` source code [https://github.com/python/cpython/blob/9cf6752276e6fcfd0c23fdb064ad27f448aaaf75/Lib/random.py](https://github.com/python/cpython/blob/9cf6752276e6fcfd0c23fdb064ad27f448aaaf75/Lib/random.py)
- Mersenne Twister Predictor [https://github.com/kmyk/mersenne-twister-predictor](https://github.com/kmyk/mersenne-twister-predictor)
- Randcrack [https://github.com/tna0y/Python-random-module-cracker](https://github.com/tna0y/Python-random-module-cracker)
- Recovery of candidate seeds when you aren't given consecutive stream of random numbers [https://ctftime.org/writeup/7331](https://ctftime.org/writeup/7331)
- Just a full on implementation of the Mersenne Twister Predictor state recovery using z3 [https://ctftime.org/writeup/15661](https://ctftime.org/writeup/15661)
- Recovering when `random.random()` float is given [https://ctftime.org/writeup/28651](https://ctftime.org/writeup/28651)