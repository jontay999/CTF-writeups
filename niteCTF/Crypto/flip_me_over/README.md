# niteCTF – Flip Me Over

- **Category:** Crypto
- **Points:** 500

## Challenge

We are given a server instance to connect to and the encrypting script `flipmeover.py`. We have to be able to send the an AES-CBC encrypted string `gimmeflag` to the server to get the flag. We are able to send a sample plaintext that would be encrypted for us but for obvious reasons, `gimmeflag` is not to be part of the string.

## Solution

1. We have to send two things when connected to the server. A token and a tag, the token is the encrypted string that we want ('gimmeflag') and tag functions like an Initialization Vector (IV)
2. The tag is XORed with every 16 bytes of our token so we have to make sure that we XOR it beforehand to make sure that that operation is negated.

   - Edit: This step was not necessary because the IV supplied would not be used for decryption.

3. This implementation is vulnerable to a bit flipping attack that is far better explained [here](https://zhangzeyu2001.medium.com/attacking-cbc-mode-bit-flipping-7e0a1c185511)
4. Essentially sending `fimmeflag` as plaintext to encrypt. Reuse the encrypted block as the IV for the next block. Flip one bit to change the `f` to a `g` and bingo.

```
from pwn import *
from Crypto.Util.strxor import strxor

first = b'0'*32+binascii.hexlify(b'fimmeflag')
print(first) #0000000000000000000000000000000066696d6d65666c6167

#send first as username and get the encrypted version
cipher = bytes.fromhex(username_encrypted)
tag = cipher[:16]
cipher = cipher[16:]

for i in range(0,len(cipher),16):
    tag = strxor(tag,cipher[i:i+16])

#flip the first bit of f into g
cipher = (cipher[0]^0b1).to_bytes(1,'little')+cipher[1:]
cipher = binascii.hexlify(cipher)

print(tag.hex())
print(cipher)
```

Running the script gets us

```
nite{flippity_floppity_congrats_you're_a_nerd}
```

## Thoughts

- More vulnerabilities learnt about aes
