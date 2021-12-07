# Cyber Santa 2021 – Meet me Halfway

- **Category:** Cryptography Day 4
- **Points:** 300
- **Difficulty:** ★☆☆☆

## Challenge

> We were given a python script that showed two rounds of AES encryption. Both instances generated a random key of 4 bytes with hexadecimal alphabet prepended/appended to a constant.

```
def gen_key(option=0):
    alphabet = b'0123456789abcdef'
    const = b'cyb3rXm45!@#'
    key = b''
    for i in range(16-len(const)):
        key += bytes([alphabet[randint(0,15)]])

    if option:
        return key + const
    else:
        return const + key

```

We were also given an instance to connect to that gave the encrypted flag along with an option to encrypt a plain text with the same keys that were used to generate the encrypted flag.

## Solution

Given that there was only 4 random bytes generated for both keys. The first thought was to brute force the keys. First I would send in a plain text of "0000" and get back the encrypted version of it. After that, try every possible combination of 2 4-byte keys until it successfully decrypts it to my original plaintext.

My original script looked something like this

```
for i in tqdm(allKeys):
    for j in allKeys:
        n2 = b'cyb3rXm45!@#' + i
        n1 = j + b'cyb3rXm45!@#'
        c1 = AES.new(n1, mode=AES.MODE_ECB)
        c2 = AES.new(n2, mode=AES.MODE_ECB)
        res1 = c1.decrypt(zero_4)
        res2 = c2.decrypt(res1)

        try:
            text = res2.decode()
        except UnicodeDecodeError:
            pass
        else:
            if('0000' in text):
                print("Message found: ", text)
                print("Key found: ", n1, n2)
                exit()
```

However with the `tqdm` module (a handy tool to figure out how long loops will take), it would take around 27 hours to try every combination of 2 4-byte keys (65536 \* 65536 combinations) so this approach was not very feasible.

> The next hint was in the title "Meet Me Halfway". Then I realised that I could try encrypting the original plaintext with every possible key and store the result in a dictionary with the key being the byte and the value being the AES encryption key. Something like

```
{"encrypted_text_from_1_aes-encryption": b"0000cyb3rXm45!@#"}
```

Then I could run every possible decryption from the encrypted known plain text and check if that decryption is in the above dictionary we just crafted, which will be O(1) lookup time.

This reduces the problem from 65536^2 iterations to just 65536 + 65536 iterations which my computer was able to complete in just a few seconds. Here's the final script.

```
def generateAllKeys():
    a = b'0123456789abcdef'
    keys = []

    for i in range(len(a)):
        for j in range(len(a)):
            for k in range(len(a)):
                for l in range(len(a)):
                    key = b''
                    key += bytes([a[i]])
                    key += bytes([a[j]])
                    key += bytes([a[k]])
                    key += bytes([a[l]])
                    keys.append(key)
    return keys

allKeys = generateAllKeys()

def smartDecrypt():
    firstD = {}
    for j in allKeys:
        n1 = j + b'cyb3rXm45!@#'
        c1 = AES.new(n1, mode=AES.MODE_ECB)
        res1 = c1.decrypt(zero_4)
        firstD[res1] = n1

    for k in allKeys:
        n2 = b'cyb3rXm45!@#' + k
        c2 = AES.new(n2, mode=AES.MODE_ECB)
        res1 = c2.encrypt(pad(bytes.fromhex('0000'), 16))
        if(res1 in firstD):
            print(n2, firstD[res1]) #key found! print both keys
```

With the 2 keys found we can easily decrypt the flag to get

```
b'https://www.youtube.com/watch?v=DZMv9XO4Nlk
HTB{m337_m3_1n_7h3_m1ddl3_0f_3ncryp710n}\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
```

The youtube link was of a rather pleasant 8 bit christmas jam.

## Thoughts

- Learnt quite a bit about AES decryption and the different modes.
- My first thought was of sending all 0s and XOR'ing it with the given ciphertext but that only work for CBC mode and not ECB mode
