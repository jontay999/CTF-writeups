# niteCTF – Variables

- **Category:** Crypto
- **Points:** 500

## Challenge

We are given some large numbers and a python script of how the encryption was done. 4 variables are randomly initialized between (0,9999999999) and used to encrypt the flag.

## Solution

1. The solution was done by using linear algebra and polynomial root finding.
2. Because we know the first 4 letters of the flag are `nite`, we can find the values of the four constants
3. Using these values we can use linear algebra to get the real roots for each polynomial equation we find.
4. Rounding the numbers off is critical at this point because as numbers get large, calculations get slightly inaccurate and character codes only accept specific integers.

```
import numpy as np

#A is the 2D matrix for solving simultaneous eqns
A = []

for i in 'nite':
    arr = []
    for j in range(3,-1,-1):
        arr.append(ord(i)**j)
    A.append(arr)

Y = enc[:4]

res = np.linalg.inv(A).dot(Y)
res = list(map(round,res))

dec = ''
for i in enc:
    arr = res[:]
    arr[-1] -= i
    #solve polynomial equations
    p = np.poly1d(arr)
    r = p.r
    dec += chr(round(r[np.isreal(r)][0].real))
print(dec)
```

Running the script gets us the flag

```
nite{jU5t_b45Ic_MaTH}
```

## Thoughts

- Was planning to do everything through `Wolfram Alpha` at first but it had a maximum character limit for equations hahah so i had to use `numpy` instead
- Realised that slight math inaccuracies can occur with big numbers in python so impt to do rounding.
