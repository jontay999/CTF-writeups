# NahamCon 2022 – Crypto Challenges

## Crypto Challenge: XORROX

### Description/Source

```python
#!/usr/bin/env python3
import random

with open("flag.txt", "rb") as filp:
    flag = filp.read().strip()

key = [random.randint(1, 256) for _ in range(len(flag))]

xorrox = []
enc = []
for i, v in enumerate(key):
    k = 1
    for j in range(i, 0, -1):
        k ^= key[j]
    xorrox.append(k)
    enc.append(flag[i] ^ v)

with open("output.txt", "w") as filp:
    filp.write(f"{xorrox=}\n")
    filp.write(f"{enc=}\n")

"""
xorrox=[1, 209, 108, 239, 4, 55, 34, 174, 79, 117, 8, 222, 123, 99, 184, 202, 95, 255, 175, 138, 150, 28, 183, 6, 168, 43, 205, 105, 92, 250, 28, 80, 31, 201, 46, 20, 50, 56]
enc=[26, 188, 220, 228, 144, 1, 36, 185, 214, 11, 25, 178, 145, 47, 237, 70, 244, 149, 98, 20, 46, 187, 207, 136, 154, 231, 131, 193, 84, 148, 212, 126, 126, 226, 211, 10, 20, 119]
"""
```

`xorrox` is an array containing continuously xored items in the key array but beginning with 1 like so

```
key = [k1, k2, k3, k4 ... k (flag length)]
xorrox = [1, k1^1, k2^k1^1, k3^k2^k1^1 ....]
```

Using this information, we can recover all the values in the key by relating the ith element of xorrox with the (i-1)th element of the array

With the key, its just a matter of decrypting the `enc` array

### Solver

```python
xorrox=[1, 209, 108, 239, 4, 55, 34, 174, 79, 117, 8, 222, 123, 99, 184, 202, 95, 255, 175, 138, 150, 28, 183, 6, 168, 43, 205, 105, 92, 250, 28, 80, 31, 201, 46, 20, 50, 56]
enc=[26, 188, 220, 228, 144, 1, 36, 185, 214, 11, 25, 178, 145, 47, 237, 70, 244, 149, 98, 20, 46, 187, 207, 136, 154, 231, 131, 193, 84, 148, 212, 126, 126, 226, 211, 10, 20, 119]

key = [1]
for i in range(1,len(xorrox)):
    key.append(xorrox[i] ^ xorrox[i-1])

print(key)
print(len(xorrox), len(enc), len(key))

s = ""
for i in range(len(enc)):
    s += chr(enc[i] ^ key[i])

print(s)
```

Note: for some reason I don't decrypt the whole flag, but it is sufficient to guess

```
Output: ag{21571dd4764a52121d94deea22214402}
Flag: flag{21571dd4764a52121d94deea22214402}
```

## Crypto Challenge: UniMod

### Description/Source

```python
import random

flag = open('flag.txt', 'r').read()
ct = ''
k = random.randrange(0,0xFFFD)
for c in flag:
    ct += chr((ord(c) + k) % 0xFFFD)

open('out', 'w').write(ct)

"""
Out File:
饇饍饂饈饜餕饆餗餙饅餒餗饂餗餒饃饄餓饆饂餘餓饅餖饇餚餘餒餔餕餕饆餙餕饇餒餒饞飫
"""
```

The out file seems like a bunch of chinese characters but they are just characters with bytes beyond the standard range of 255. It is important not to read the file in as bytes like `open("out", "rb")` because that will interpret each character as multiple bytes.

Given the small range of k `[0-0xFFFD]`, it is easily bruteforceable. If 'flag' is in the decrypted string (or if it can even be decoded to ascii) then it is the flag

### Solver

```python
lim = 0xFFFD
a = "饇饍饂饈饜餕饆餗餙饅餒餗饂餗餒饃饄餓饆饂餘餓饅餖饇餚餘餒餔餕餕饆餙餕饇餒餒饞飫"
arr = [ord(i) for i in a]

for i in range(lim):
    s = ""
    try:
        for x in arr:
            char = (x-i) % lim
            assert char < 256
            s += chr(char)
        if "flag" in s:
            print(s)
    except:
        continue

```

### Flag

```
flag{4e68d16a61bc2ea72d5f971344e84f11}
```
