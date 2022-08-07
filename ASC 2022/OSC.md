## Crypto Challenge: OSC

### Description/Source

```py
#!/usr/bin/env python3
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long, isPrime
from string import printable, ascii_letters
from secret import FLAG
import os

secret = os.urandom(len(FLAG))

def OSP(plain, secret):
    assert len(plain) == len(secret), 'The length has to be idenntical!'
    ct = []
    p = getPrime(256)
    for f, k in zip(FLAG, secret):
        ct.append((f * p + k))
    return ct, p

ct, p = OSP(FLAG, secret)
print(ct)
```

Each ith character of the flag, $f_i$ is encrypted by

$$
c_i = f_i * p + k_i
$$

Where $p$ is a 256 bit prime and a random secret $k$. The solution is based on the assumption that each character of the secret is not as large as the prime $p$, thus the term $f_i * p$ will dominate each encryption. Since we know how that the flag starts with `ASCWG{`, we can use that to determine the prime $p$ with floor division

### Solver

```python
from libnum import *
from Crypto.Util.number import *

ct = [
    5447072546591309544167389173397699795993168970119080464536675615517059887871841,
    6955492636416595264090666175261678201037431146459748900869908862891014933743799,
    5614674778794119068603308840271475174331420323045821401907034865225277115190905,
    7290697100822214312962505509009228957713933852313230775610627362307449388382150,
    5949879243199738117475148174019025931007923028899303276647753364641711569829134,
    10307537280472785752809059512737185767802458204994567648277093857055359480126320
]
# ASCWG❴...answer❵
known = b'ASCWG{'

# prime
p = None
for i in range(len(known)):
    res = (ct[i] // known[i])
    if isPrime(res):
        p = res
        print('P:', res, 'bits:', res.bit_length())

flag = ""
with open('output.txt', 'r') as f:
    for line in f.readlines():
        char = eval(line.strip())
        flag += chr(char // p)
print(flag)


```

### Flag

```
ASCWG{Wh47_1f_17's_N07_@_Pr1M3!-f0ffa3657e}
```
