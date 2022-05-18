# Cyber Santa 2021 – Missing Reindeer

- **Category:** Cryptography Day 3
- **Points:** 300
- **Difficulty:** ★☆☆☆

## Challenge

We are given a `message.eml` file which was an email chain exchanged between "Pep Sparkles" and "Tiny Jingles" who have hidden away a reindeer. The location of the reindeer was encrypted using RSA once again.

We are given both the cipher text, and a base64 encoded Public Key used.

## Solution

To find out more about the public key, I used the `openssl` utility

```
openssl rsa -pubin -text -in publickey.txt
```

which gave information that while the modulus was very large, the exponent was very small

```
Public-Key: (2048 bit)
Modulus:
    00:e6:23:97:28:84:b1:f4:d7:22:bd:d5:ee:5b:eb:
    84:cb:84:76:0c:2e:d0:ff:af:d9:3c:d6:03:0f:b2:
    0d:79:30:90:3b:d1:73:1d:c7:4c:95:4a:23:07:53:
    03:df:d7:1b:88:5c:d6:6e:98:5b:f7:59:ed:17:a9:
    85:f7:e7:d8:37:c8:57:bd:31:a1:47:d7:4d:a2:61:
    49:28:58:fa:5f:cf:b8:92:30:87:8e:f4:ff:fc:ff:
    92:fc:29:29:89:32:64:54:af:b5:1b:b7:ab:25:3f:
    ef:d5:b3:57:bf:83:a6:39:f1:53:20:4a:fc:56:28:
    f3:e0:20:22:c6:94:9d:c2:3c:b1:9d:2f:d6:39:b6:
    d5:98:7a:c3:32:a0:1d:d2:3b:43:7a:67:77:bb:96:
    7f:80:e5:22:e9:41:e5:f9:72:16:0a:ed:55:6d:b7:
    39:39:19:80:64:22:ae:1a:7d:c9:b1:99:96:fd:b7:
    b2:91:41:47:2d:68:03:df:f4:2a:71:3d:b5:7a:c0:
    78:fc:a4:8d:1a:68:61:42:3d:e3:a1:2e:d9:cf:af:
    b8:31:e5:d6:9b:92:d7:19:63:d0:23:22:8c:26:12:
    ea:33:4a:65:2c:46:12:1f:50:5d:1b:5a:55:12:24:
    c6:9f:c8:23:9c:fe:10:93:de:68:09:5f:71:53:15:
    96:67
Exponent: 3 (0x3)
```

In RSA the cipher is encrypted via the function:

- `ciphertext = plaintext^exponent % modulus`.

But with such a large modulus and small exponent, it was very likely that the modulus was never used. By running a function to cube root the ciphertext, (Note: the `find_invpower` function was found [here](https://stackoverflow.com/questions/356090/how-to-compute-the-nth-root-of-a-very-big-integer) on StackOverflow)

```
def find_invpow(x,n):
    high = 1
    while high ** n < x:
        high *= 2
    low = high//2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

decoded = int.from_bytes(base64.b64decode(secret), 'big')
answer = find_invpow(decoded, 3)

print(long_to_bytes(answer))

```

And bingo, we have the reindeer's location.

```
We are in Antarctica, near the independence mountains.\nHTB{w34k_3xp0n3n7_ffc896}
```

## Thoughts

- Again finding more vulnerabilities in RSA
- While the algorithm itself is secure, its strength lies in the utility of big numbers. If big numbers are not used, it becomes vulnerable to such attacks
- It was surprisingly hard to find a function that found the polynomial root of a number and I had to resort to stackoverflow hahha
