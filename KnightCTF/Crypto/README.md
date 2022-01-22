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
