# Crypto - Block (375)

## Challenge

```python
from Crypto.Util.Padding import pad

FLAG = <REDACTED>

SUB_KEY = [
    0x11,0x79,0x76,0x8b,0xb8,0x40,0x02,0xec,0x52,0xb5,0x78,0x36,0xf7,0x19,0x55,0x62,
    0xaa,0x9a,0x34,0xbb,0xa4,0xfc,0x73,0x26,0x4b,0x21,0x60,0xd2,0x9e,0x10,0x67,0x2c,
    0x32,0x17,0x87,0x1d,0x7e,0x57,0xd1,0x48,0x3c,0x1b,0x3f,0x37,0x1c,0x93,0x16,0x24,
    0x13,0xe1,0x1f,0x91,0xb3,0x81,0x1e,0x3d,0x5b,0x6c,0xb9,0xf2,0x83,0x4c,0xd5,0x5a,
    0xd0,0xe7,0xca,0xed,0x29,0x90,0x6f,0x8f,0xe4,0x2f,0xab,0xbe,0xfe,0x07,0x71,0x6b,
    0x59,0xa3,0x8a,0x5e,0xd7,0x30,0x2a,0xa0,0xac,0xbd,0xd4,0x08,0x4f,0x06,0x31,0x72,
    0x0d,0x9f,0xad,0x0b,0x23,0x80,0xe6,0xda,0x75,0xa8,0x18,0xe2,0x04,0xeb,0x8e,0x15,
    0x64,0x00,0x2b,0x03,0xa1,0x5d,0xb4,0xb1,0xf0,0x97,0xe3,0xe8,0xb0,0x05,0x86,0x38,
    0x56,0xef,0xfa,0x43,0x94,0xcb,0xb6,0x69,0x5f,0xc7,0x27,0x7c,0x44,0x8d,0xf3,0xc8,
    0x99,0xc2,0xbc,0x82,0x65,0xdb,0xaf,0x51,0x20,0x7f,0xc3,0x53,0xf4,0x33,0x4d,0x50,
    0xee,0xc5,0x12,0x63,0x9b,0x7b,0x39,0x45,0xa9,0x2d,0x54,0xdc,0xdf,0xd6,0xfd,0xa7,
    0x5c,0x0c,0xe9,0xb2,0xa2,0xc1,0x49,0x77,0xae,0xea,0x58,0x6d,0xce,0x88,0xf8,0x96,
    0xde,0x1a,0x0f,0x89,0xd3,0x7a,0x46,0x22,0xc6,0xf9,0xd9,0x84,0x2e,0x6a,0xc9,0x95,
    0xa5,0xdd,0xe0,0x74,0x25,0xb7,0xfb,0xbf,0x9c,0x4a,0x92,0x0e,0x09,0x9d,0xf6,0x70,
    0x61,0x66,0xc0,0xcf,0x35,0x98,0xf5,0x68,0x8c,0xd8,0x01,0x3e,0xba,0x6e,0x41,0xf1,
    0xa6,0x85,0x3a,0x7d,0xff,0x0a,0x14,0xe5,0x47,0xcd,0x28,0x3b,0xcc,0x4e,0xc4,0x42
]

def xor(block):
    for i in range(4):
        for j in range(4):
            block[i][j] ^= block[(i + 2) % 4][(j + 1) % 4]

def add(block):
    for i in range(4):
        for j in range(4):
            block[i][j] += 2 * block[(i * 3) % 4][(i + j) % 4]
            block[i][j] &= 0xFF

def sub(block):
    for i in range(4):
        for j in range(4):
            block[i][j] = SUB_KEY[block[i][j]]

def rotate(row):
    row[0], row[1], row[2], row[3] = row[3], row[0], row[1], row[2]

def transpose(block):
    copyBlock = [[block[i][j] for j in range(4)] for i in range(4)]

    for i in range(4):
        for j in range(4):
            block[i][j] = copyBlock[j][i]

def swap(block):
    block[0], block[2] = block[2], block[0]
    block[3], block[2] = block[2], block[3]
    block[0], block[1] = block[1], block[0]
    block[3], block[0] = block[3], block[0]
    block[2], block[1] = block[1], block[2]
    block[2], block[0] = block[0], block[2]

    rotate(block[0]); rotate(block[0])
    rotate(block[1]); rotate(block[1]); rotate(block[1])
    rotate(block[2])
    rotate(block[3]); rotate(block[3]); rotate(block[3])

    for i in range(3):
        for j in range(4):
            ii = ((block[i][j] & 0XFC) + i) % 4
            jj = (j + 3) % 4
            block[i][j], block[ii][jj] = block[ii][jj], block[i][j]

    s = 0
    for i in range(4):
        for j in range(4):
            s += block[i][j]

    if (s % 2): transpose(block)

def round(block):
    sub(block)
    add(block)
    swap(block)
    xor(block)

def encryptBlock(block):
    mat = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
    for _ in range(30):
        round(mat)
    return [mat[i][j] for i in range(4) for j in range(4)]

def encrypt(msg):
    msg = list(pad(msg, 16))
    enc = []
    for i in range(0, len(msg), 16):
        enc += encryptBlock(msg[i : i + 16])
    return bytes(enc)

print(encrypt(FLAG).hex())

# 1333087ba678a43ecc697247e2dde06e1d78cb20d8d9326e7c4b01674a46647674afc1e7edd930828e40af60b998b4500361e3a2a685c5515babe4e9ff1fe882
```

We are given a cipher whose way of encryption is 4 methods: substitution, adding, swapping (permuting), and xor-ing. This is done 30 times for each block of 16 bytes, in the following manner

```python

def round(block):
    sub(block)
    add(block)
    swap(block)
    xor(block)

def encryptBlock(block):
    mat = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
    for _ in range(30):
        round(mat)
    return [mat[i][j] for i in range(4) for j in range(4)]
```

Typically such systems will have a secret key to actually mix things up, making the problem a much harder one of linear/differential cryptanalysis, but it seems we are provided no server and no key, so each of the operations can just be reversed individually.

1. Reversing the XOR function

```python
def xor(block):
    for i in range(4):
        for j in range(4):
            block[i][j] ^= block[(i + 2) % 4][(j + 1) % 4]
```

The inverse of the xor function is just itself, so to reverse it, just traverse the 2D array in the reverse manner

```python
def xor_rev(block):
    for i in range(3,-1,-1):
        for j in range(3,-1,-1):
            block[i][j] ^= block[(i + 2) % 4][(j + 1) % 4]
```

2. Reversing the add function

```python
def add(block):
    for i in range(4):
        for j in range(4):
            block[i][j] += 2 * block[(i * 3) % 4][(i + j) % 4]
            block[i][j] &= 0xFF
```

This was slightly tougher to reverse, and also the only part of the `round` encryption that actually changed the original values of the block. If this operation didn't exist,  each input byte could just be mapped to its new position without reversing the individual functions. This addition uses information from another row `(i*3)%4` and column `(i+j)%4` and adds that value twice to its original value. For the 2nd to 4th row, the operations could be just reversed with subtraction. However, the first row is simply multiplying the original value by 3, because the given the `jth` column of the first operation evaluates to `block[0][j] += 2 * block[0][j]`. This operation could be reversed by calculating `inverse_mod(3,256)`. Note: the mod 256 appears in the last column to make ensure that the remaining values are within byte range. `block[i][j] &= 0xFF`

```python
def add_rev(block):
    for i in range(3,-1,-1):
        for j in range(3,-1,-1):
            if i == 0:
                block[i][j] *= 171 #inverse_mod(3,256)
                block[i][j] &= 0xFF
            else:
                block[i][j] -= 2 * block[(i * 3) % 4][(i + j) % 4]
                block[i][j] &= 0xFF
```

3. Reversing the swap function

```python

def rotate(row):
    row[0], row[1], row[2], row[3] = row[3], row[0], row[1], row[2]

def transpose(block):
    copyBlock = [[block[i][j] for j in range(4)] for i in range(4)]

    for i in range(4):
        for j in range(4):
            block[i][j] = copyBlock[j][i]

def swap(block):
    block[0], block[2] = block[2], block[0]
    block[3], block[2] = block[2], block[3]
    block[0], block[1] = block[1], block[0]
    block[3], block[0] = block[3], block[0]
    block[2], block[1] = block[1], block[2]
    block[2], block[0] = block[0], block[2]

    rotate(block[0]); rotate(block[0])
    rotate(block[1]); rotate(block[1]); rotate(block[1])
    rotate(block[2])
    rotate(block[3]); rotate(block[3]); rotate(block[3])

    for i in range(3):
        for j in range(4):
            ii = ((block[i][j] & 0XFC) + i) % 4
            jj = (j + 3) % 4
            block[i][j], block[ii][jj] = block[ii][jj], block[i][j]

    s = 0
    for i in range(4):
        for j in range(4):
            s += block[i][j]

    if (s % 2): transpose(block)
```

While it looks really complicated, it just shuffles around each value in the cell to a deterministic locations and transposing the final 2D array if the sum of all the values are odd. Its not necessary to actually reverse each of these operations (while feasible), but instead simply keeping a mapping of input byte location to final byte location, in both scenarios of odd and even would be sufficient to reverse it. This mapping can be retrieved by passing a regular block of `[0,1,2,3,...15]` (pass in 16 as the last number for a different block sum parity) and check their final output locations, taking note of its index.

```python
def getMap(isEven):
    block = bytes([i for i in range(16)])
    block = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
    if(isEven): block[-1][-1] += 1
    swap(block)
    mapping = []
    for i in range(4):
        for j in range(4):
            if block[i][j] == 16:
                block[i][j] -=1
            mapping.append(block[i][j])
    return mapping

def swap_rev(block):
    isEven = sum(sum(block,[])) % 2 == 0
    permMap = getMap(isEven)

    copy = []
    for i in block:
        copy.append(i[:])

    for i in range(4):
        for j in range(4):
            idx = permMap.index(i*4+j)
            block[i][j] = copy[idx%4][idx//4]
    return block
```

4. Reversing the sub operation

```python
def sub(block):
    for i in range(4):
        for j in range(4):
            block[i][j] = SUB_KEY[block[i][j]]
```

Given the existing mapping using the `SUB_KEY` we can shift the original element back to its index of SUB_KEY

```python
def sub_rev(block):
    for i in range(4):
        for j in range(4):
            block[i][j] = SUB_KEY.index(block[i][j])
```

And we're done! Just pass the cipher text blocks through these reversed functions 30 times and we've got ourselves the flag!

## Solution

```python

SUB_KEY = [
    0x11,0x79,0x76,0x8b,0xb8,0x40,0x02,0xec,0x52,0xb5,0x78,0x36,0xf7,0x19,0x55,0x62,
    0xaa,0x9a,0x34,0xbb,0xa4,0xfc,0x73,0x26,0x4b,0x21,0x60,0xd2,0x9e,0x10,0x67,0x2c,
    0x32,0x17,0x87,0x1d,0x7e,0x57,0xd1,0x48,0x3c,0x1b,0x3f,0x37,0x1c,0x93,0x16,0x24,
    0x13,0xe1,0x1f,0x91,0xb3,0x81,0x1e,0x3d,0x5b,0x6c,0xb9,0xf2,0x83,0x4c,0xd5,0x5a,
    0xd0,0xe7,0xca,0xed,0x29,0x90,0x6f,0x8f,0xe4,0x2f,0xab,0xbe,0xfe,0x07,0x71,0x6b,
    0x59,0xa3,0x8a,0x5e,0xd7,0x30,0x2a,0xa0,0xac,0xbd,0xd4,0x08,0x4f,0x06,0x31,0x72,
    0x0d,0x9f,0xad,0x0b,0x23,0x80,0xe6,0xda,0x75,0xa8,0x18,0xe2,0x04,0xeb,0x8e,0x15,
    0x64,0x00,0x2b,0x03,0xa1,0x5d,0xb4,0xb1,0xf0,0x97,0xe3,0xe8,0xb0,0x05,0x86,0x38,
    0x56,0xef,0xfa,0x43,0x94,0xcb,0xb6,0x69,0x5f,0xc7,0x27,0x7c,0x44,0x8d,0xf3,0xc8,
    0x99,0xc2,0xbc,0x82,0x65,0xdb,0xaf,0x51,0x20,0x7f,0xc3,0x53,0xf4,0x33,0x4d,0x50,
    0xee,0xc5,0x12,0x63,0x9b,0x7b,0x39,0x45,0xa9,0x2d,0x54,0xdc,0xdf,0xd6,0xfd,0xa7,
    0x5c,0x0c,0xe9,0xb2,0xa2,0xc1,0x49,0x77,0xae,0xea,0x58,0x6d,0xce,0x88,0xf8,0x96,
    0xde,0x1a,0x0f,0x89,0xd3,0x7a,0x46,0x22,0xc6,0xf9,0xd9,0x84,0x2e,0x6a,0xc9,0x95,
    0xa5,0xdd,0xe0,0x74,0x25,0xb7,0xfb,0xbf,0x9c,0x4a,0x92,0x0e,0x09,0x9d,0xf6,0x70,
    0x61,0x66,0xc0,0xcf,0x35,0x98,0xf5,0x68,0x8c,0xd8,0x01,0x3e,0xba,0x6e,0x41,0xf1,
    0xa6,0x85,0x3a,0x7d,0xff,0x0a,0x14,0xe5,0x47,0xcd,0x28,0x3b,0xcc,0x4e,0xc4,0x42
]

def getMap(isEven):
    block = bytes([i for i in range(16)])
    block = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
    if(isEven): block[-1][-1] += 1
    swap(block)
    evenMap = []
    for i in range(4):
        for j in range(4):
            if block[i][j] == 16: block[i][j] -=1
            evenMap.append(block[i][j])
    return evenMap

def xor_rev(block):
    for i in range(3,-1,-1):
        for j in range(3,-1,-1):
            block[i][j] ^= block[(i + 2) % 4][(j + 1) % 4]


def add_rev(block):
    for i in range(3,-1,-1):
        for j in range(3,-1,-1):
            if i == 0:
                block[i][j] *= 171 #invert(3,256)
                block[i][j] &= 0xFF
            else:
                block[i][j] -= 2 * block[(i * 3) % 4][(i + j) % 4]
                block[i][j] &= 0xFF

def sub_rev(block):
    for i in range(4):
        for j in range(4):
            block[i][j] = SUB_KEY.index(block[i][j])


def sub(block):
    for i in range(4):
        for j in range(4):
            block[i][j] = SUB_KEY[block[i][j]]

def rotate(row):
    row[0], row[1], row[2], row[3] = row[3], row[0], row[1], row[2]

def transpose(block):
    copyBlock = [[block[i][j] for j in range(4)] for i in range(4)]

    for i in range(4):
        for j in range(4):
            block[i][j] = copyBlock[j][i]

def swap(block):
    block[0], block[2] = block[2], block[0]
    block[3], block[2] = block[2], block[3]
    block[0], block[1] = block[1], block[0]
    block[3], block[0] = block[3], block[0]
    block[2], block[1] = block[1], block[2]
    block[2], block[0] = block[0], block[2]

    rotate(block[0]); rotate(block[0])
    rotate(block[1]); rotate(block[1]); rotate(block[1])
    rotate(block[2])
    rotate(block[3]); rotate(block[3]); rotate(block[3])

    for i in range(3):
        for j in range(4):
            ii = ((block[i][j] & 0XFC) + i) % 4
            jj = (j + 3) % 4
            block[i][j], block[ii][jj] = block[ii][jj], block[i][j]

    s = 0
    for i in range(4):
        for j in range(4):
            s += block[i][j]

    if (s % 2):
        transpose(block)

def swap_rev(block):
    isEven = sum(sum(block,[])) % 2 == 0
    permMap = getMap(isEven)

    copy = []
    for i in block:
        copy.append(i[:])

    for i in range(4):
        for j in range(4):
            idx = permMap.index(i*4+j)
            block[i][j] = copy[idx%4][idx//4]
    return block


def round_rev(block):
    xor_rev(block)
    swap_rev(block)
    add_rev(block)
    sub_rev(block)

ct = bytes.fromhex('1333087ba678a43ecc697247e2dde06e1d78cb20d8d9326e7c4b01674a46647674afc1e7edd930828e40af60b998b4500361e3a2a685c5515babe4e9ff1fe882')

def decryptBlock(block):
    mat = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
    for _ in range(30):
        round_rev(mat)
    return [mat[i][j] for i in range(4) for j in range(4)]

def decrypt(msg):
    dec = []
    for i in range(0, len(msg), 16):
        dec += decryptBlock(msg[i : i + 16])
    return bytes(dec)

print(decrypt(ct))


```

## Flag

```
grey{I_think_I_forgot_to_put_in_my_secret..._3xPDBY9Xq5PtqjVA}\x02\x02
```
