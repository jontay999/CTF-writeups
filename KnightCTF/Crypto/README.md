# KnightCTF 2022 – Crypto Challenges

## Challenge 1: Passwd (25 points)

A text file is given,that looked like a `/etc/passwd` file and the prompt was to find out the password of the 'knight' user

```
root:x:0:0:root:/root:/usr/bin/zsh
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
[...many more users]
knight:x:708697c63f7eb369319c6523380bdf7a:/home/junior:/bin/zsh
```

### Solution

1. Entering the hash into a [hash identifier](https://www.tunnelsup.com/hash-analyzer/) showed that it was a MD5 hash.
2. Decrypting it [here](https://www.md5online.org/md5-decrypt.html) showed that the plaintext was `exploit`.

### Flag

```
KCTF{exploit}
```

## Challenge 2: 404 (25 points)

A link was given that redirects to a 404 page.

```
https://knightsquad.org/KCTF-2022?cypto=03MTJ3M2NjcfBDdfR2Mz42X1BTefN3MNFDdz0EMTtnRUN0S
```

- There wasn't a lot to go on from here, and the message from the admins was that there was no fuzzing necessary so it probably wasn't something in the site.
- The characters were base64 but did not decode to anything intelligible

### Solution

1. I had the idea of reversing the string because the url param began with an equals sign which base64 strings usually have for padding

2. Solution script

```
import base64
string = "=03MTJ3M2NjcfBDdfR2Mz42X1BTefN3MNFDdz0EMTtnRUN0S"
base64.b64decode(string[::-1])
```

### Flag

```
KCTF{S0M3t1M3s_y0u_n33d_t0_r3v3rS3}
```

## Challenge 3: Jumble (50 points)

Two files were given

- A cipher text with base64 characters
- The python script used to encode the text

Essentially the encryption function swaps the ith character with the (i+1)th character in a nested loop.

```
def f(t):
    c = list(t)
    for i in range(len(t)):
        for j in range(i, len(t) - 1):
            c[j], c[j+1] = c[j+1], c[j]
    return "".join(c)
```

### Solution

1. Rather than just write a function to reverse this swapping of characters, I decided to use an array of the same length with their original indexes as values and run it through the same encryption function

2. After the values in that array have been jumbled, I can just use these new values to match the jumbled characters with their corresponding indices

3. Solution Script

```
import base64
with open('ciphertext', 'r') as f:
    data = f.read()

arr = [i for i in range(len(data))]

for i in range(len(data)):
    for j in range(i, len(data) - 1):
        arr[j], arr[j+1] = arr[j+1], arr[j]

flag = ["" for _ in range(len(data))]
for i in range(len(data)):
    flag[arr[i]] = data[i]
b64_flag = ''.join(flag)
print(base64.b64decode(b64_flag))
```

### Flag

```
KCTF{y0u_g0t_m3}
```

## Challenge 4: Pairs (50 points)

### Disclaimer: I did not manage to solve this

Only a prompt was given

```
My brother sent me the following message, "37n3vq6s45ch6731bn4pg6gh5tr2z76kf2nt5zc56a6w0"

Can you help me to understand this message?
```

The only thing I noticed was that it had base36 characters. Dcode's cipher identifier and running it through a bunch of cyber chef decodings didn't help.

Other ideas I had was that it represented a large number in base 36 and that maybe you had to factor it into possibly 2 numbers of similar length and xor them together... it was a long shot and didn't work anyway

### Solution

The solution was simply to stumble upon this [website](https://www.calcresult.com/misc/cyphers/twin-hex.html) which just showed that it was a twin hex cipher.

The website didn't explain very well how it worked so I took a look at the source code of their description.

- First an array is generated of all possible pairs of ascii characters (from char code 32 to 127) which gives an array of 9216 characters

```
function getCypherBase() {
    var outArray = [];
    var thisPair = "";
    for (var x = 32; x < 128; x++) {
        for (var y = 32; y < 128; y++) {
            thisPair = String.fromCodePoint(x) + String.fromCodePoint(y);
            outArray.push(thisPair);
        }
    }
    return outArray;
}
console.log(getCypherBase())
// code taken from website
```

`[ ' ', ' !', ' "', ' #', ' $', ' %', ' &', " '", ' (', ' )', ' *', ' +', ' ,', ' -', ' .', ' /', ' 0', ' 1', ' 2', ' 3', ' 4', ' 5', ' 6', ' 7', ' 8', ' 9', ' :', ' ;', ' <', ' =', ' >', ' ?' ...] `

- To decrypt an encoded input, the input is split into an array with elements containing 3 characters and blank characters if
  - So "abcde" would become ["abc", "de "] which is the input array
- Each element is then converted from base36 to a number which corresponds to the index of the character pair

- For Example:
  - the beginning of the cipher was "37n3vq..."
  - Assume `char_table` contains the aforementioned table of characters

(JavaScript)

```
char_table[parseInt('37n', 36)] // 'KC'
char_table[parseInt('3vq', 36)] // 'TF'
```

- Just repeat this for the rest of the flag, and voila

- Thoughts: IMO not a very good challenge because there was no way to get the flag unless you knew of twin hex cipher? Googling twin hex cipher also doesn't give anything helpful except that particular website.

### Flag

```
KCTF{Th1s_1s_Tw1n_H3x_Cypher}
```

## Challenge 5: RSA-One (100 points)

We are given 2 files

1. The encoded flag in `flag.enc`
2. A `private.pem` file with the RSA key but with one character missing and replaced by ❌

Since the private key is only made out of base64 characters, the straightforward approach is to brute force every possible character and try to decrypt i.

### Solution Script

- I had some trouble reading the private key using python's rsa library so I resorted to just converting it to a string and using the `os` library to run commands
- By replacing the ❌ with the character, writing it to a `sample.pem` and trying to decrypt using openssl utility, it revealed that the missing character was `A`.

```
with open('flag.enc', 'rb') as f:
    data = f.read()

sample = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyiytHt1AKzYLwZPm1dd9uT7LgsqVj0eSLpheNd0H4xyiZCYG
ZtRYnNtGNnq7A/ubyFalExm61QNewfy71h6xhM/❌IEIoNT0VfMOIzcq0Jmoh+v6k
[...]
xqG9YAHVmm4iJzcHeMdzLwmzR6D/x6+k2cFWwox6PxvA7ikJQEYr
-----END RSA PRIVATE KEY-----


baseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

import os
for i in baseLetters:
    new = sample.replace('❌', i)
    with open('sample.pem', 'w') as f:
        f.write(new)
    try:
        os.system("openssl rsautl -decrypt -inkey sample.pem -in flag.enc -out flag.txt")
        os.system("cat flag.txt")
    except:
        print(f"Error, skipping {i}")
"""
```

### Flag

```
KCTF{M4Y_TH3_8RUT3F0rc3_B3_W1TH_Y0U}
```

## Challenge 6: Alphabetknock Code (100 points)

We are given a cipher consisting of a bunch of dots separated by spaces.

- Googling alphabet knock led to discovery of the tap code cipher
- The prompt also gives a few hints that
  - C = K
  - Y = Z
  - total number is 24
- The default way of using tap code uses a 5x5 grid but that doesn't fit with the constraints of the prompt and cipher (there were 6 dots in parts of the cipher)

Cipher

```
... ......  . .....  . ...  ... .....  . .....  .... ..  . ...  ... .  .. ...  .. .  .. ..  .... ..
```

### Solution

- Tap Code works by making a grid with the relevant alphabet. The first number of dots would indicate the row and the second word made of dots would indicate the column which would then combine to give a letter
- The grid formed was with the necessary replacements

```
A B K D E F
G H I J L M
N O P Q R S
T U V W X Z
```

- This led to the decoded version `SEKREUKNIGHU`
- The flag looked a bit strange but with a bit of intuition, it could be deduced that the U and T swapped places and the flag spelled `SECRETKNIGHT`

### Flag

```
KCTF{SECRETKNIGHT}
```

## Challenge 7: Tony Stark needs Help (150 points)

We are given a `letter.txt` that has the encrypted cipher as well as possible keys to the cipher.

```
...
And here are the clue keys for activating the Fat Boy:

- T3NR1NG$
- T3nR1ng$
- TenRings
- T3nR!ngs
- T3nR!ng$
- 73NR1GN$
- 73nRing$
- T3nR!nG$
...
```

`encrypt.py` was given also that showed the encryption algorithm.

```
secret = input("Enter your string to encrypt: ")
key = input("Enter the key: ")

secarr = []
keyarr = []
x = 0

def keyfunc(key,keyarr,x):
    for character in key:
        keyarr.append(ord(character))

    for i in keyarr:
        x += i

def secretfucn(secret,secarr,key,x):
    for character in secret:
        secarr.append(ord(character))
    for i in range(len(secarr)):
        if 97 <= secarr[i] <= 122:
            secarr[i] = secarr[i]-6
        else:
            if 65 <= secarr[i] <= 90:
                secarr[i] = secarr[i]-11
    if len(key) % 2 == 0:
        x = x + 1
    else:
        x = x + 3
    if x % 2 == 0:
        secarr[i] = secarr[i] + 3
    else:
        secarr[i] = secarr[i] + 2
    encrypted = ""
    for val in secarr:
        encrypted = encrypted + chr(val)
    print("Encrypted Text: " + encrypted)
keyfunc(key,keyarr,x)
secretfucn(secret,secarr,key,x)
```

There are 2 pieces of information from the `letter.txt` that should be extracted, a deactivation passphrase and a location, both of which were encrypted with the same algorithm

### Solution

- The script did not explicitly use the key to encrypt but used the length of the key instead. All the keys provided had the same length so it wasn't necessary to know the exact key used
- Not much to talk about the decryption, simply just reverse all the operations done
  - e.g. +11 to ascii character code becomes -11 and adjust the ranges of if statements accordingly

Solution Script

```
ct = "IihsIb_7[^7is<inH][l_^D`Ib_;[n7iu"

keys = [
"T3NR1NG$",
"T3nR1ng$",
"TenRings",
"T3nR!ngs",
"T3nR!ng$",
"73NR1GN$",
"73nRing$",
"T3nR!nG$",
]


def secretfucn(secret,secarr,key,x):
    for character in secret:
        secarr.append(ord(character))
    for i in range(len(secarr)):
        if 97 <= secarr[i] <= 122:

            secarr[i] = secarr[i]-6
        else:
            if 65 <= secarr[i] <= 90:
                secarr[i] = secarr[i]-11
    if len(key) % 2 == 0:
        x = x + 1
    else:
        x = x + 3
    if x % 2 == 0:
        secarr[i] = secarr[i] + 3
    else:
        secarr[i] = secarr[i] + 2
    encrypted = ""
    for val in secarr:
        encrypted = encrypted + chr(val)
    print("Encrypted Text: " + encrypted)

def reverse_decrypt(txt):
    secarr = []
    final = ""
    for i in range(len(txt)):
        secarr.append(ord(txt[i]))
    secarr[i] -= 2
    x = 7

    for j in range(len(secarr)):
        if(91<= secarr[j] <= 116):
            secarr[j] += 6
        else:
            if 54 <= secarr[j] <= 79:
                secarr[j] += 11
    for k in secarr:
        final += chr(k)
    print(final)

reverse_decrypt(ct)
reverse_decrypt("6G:653") #location encrypted
```

### Flag

Flag format was KCTF{NAMEOFTHEPLACE_PasswordForDeactivation}

```
KCTF{AREA51_TonyTheBadBoyGotScaredOfTheFatBoy}
```

## Challenge 8: Feistival (150 points)

We are given a `cipher.txt` and an `enc.py`

The encryption was fairly interesting

```
m, n = 21, 22
def f(word, key):
    out = ""
    for i in range(len(word)):
        out += chr(ord(word[i]) ^ key)
    return out

flag = open("flag.txt", "r").read()

L, R = flag[0:len(flag)//2], flag[len(flag)//2:]
x = "".join(chr(ord(f(R, m)[i]) ^ ord(L[i])) for i in range(len(L)))
y = f(R, 0)

L, R = y, x
x = "".join(chr(ord(f(R, n)[i]) ^ ord(L[i])) for i in range(len(L)))
y = f(R, 0)

ciphertext = x + y
ct = open("cipher.txt", "w")
ct.write(ciphertext)
ct.close()
```

- Basically you split the flag into two equal parts L,R
- The `f(word,key)` function basically just xors every character in the word with the key provided
  - `f(R,0)` doesn't change anything to R because xor-ing with 0 doesn't affect anything

### Solution

We are given the 2 keys that are used to encrypt which are 21 and 22. So just following the functions we just need to xor the relevant parts of the cipher with the variables used to encrypt it.

```
with open('cipher.txt', 'rb')as f:
    data = list(f.read())

m,n = 21,22
L = 12

first = ""
arr = []
for i in range(12):
    arr.append(data[i]^22^21)
    first += chr(data[i]^22^21)
second = ""
for i in range(12):
    second += chr(data[12+i]^arr[i] ^21)
print(first+second)
```

### Flag

```
KCTF{feistel_cipher_ftw}
```

# Conclusion

That's about it for all the crypto challenges I've looked at. Didn't manage to have enough time to look at the final challenge.
