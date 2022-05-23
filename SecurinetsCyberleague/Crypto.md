# Securinets Esprit CyberLeague 2022 – Crypto Challenges

We managed to clear all the Crypto challenges! Because I joined a bit late, I only solved from `T-shains` to `Polllis`.

![solve](./images/solve.png)

Because there are many challenges, I will just outline the main vulnerability.

(Haven't decided if I'll do a writeup for Crypto Cybercup yet...)

## Challenge 1: T-shains

### Description/Source

```python
flag = b64encode(flag)
enc = b""
for i in range(len(flag)):
	enc += bytes([flag[i] ^ flag[(i+1) %len(flag)]])
enc = b64encode(enc)
# Z1oYPRg5GS1qfAcHCgIJF2p7e3wKHWloaH4hIQoCMzwaFnho
```

This can be easily bruteforced. Guess the first character of the flag, and then using that derive the full decryption of the guessed flag. If the resulting base64 is able to be decoded to ascii then it likely is correct. A slight optimization would be to move on to the next guess once the decoded character is not within the printable ASCII range (33 - 127)

### Solver

```python
from base64 import b64decode
c = "Z1oYPRg5GS1qfAcHCgIJF2p7e3wKHWloaH4hIQoCMzwaFnho"
c = b64decode(c)


printable = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
for i in list(printable):
    flag = i
    fail = False
    for idx in range(len(c)):
        char = chr(c[idx] ^ ord(flag[-1]))
        if 33<= ord(char) <= 127:
            flag += char
        else:
            fail = True
            break
    try:
        print(b64decode(flag).decode('utf-8'))
    except:
        pass


```

### Flag

```
Securinets{Shi1In_cH41N_b6464_Ch41n!!}
```

## Challenge 2: DaVinci Secret Room

### Description/Source

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from secrets import flag
import random
import os

BLOCK_SIZE = 16
KEY = os.urandom(BLOCK_SIZE)

def encrypt(msg):
	iv = os.urandom(BLOCK_SIZE)
	cipher = AES.new(KEY, AES.MODE_CBC, iv)
	return (iv + cipher.encrypt(pad(msg, BLOCK_SIZE))).hex()


def decrypt(data):
	iv = data[:BLOCK_SIZE]
	cipher = AES.new(KEY, AES.MODE_CBC, iv)
	return unpad(cipher.decrypt(data[BLOCK_SIZE:]), BLOCK_SIZE)

def parse(enc_token):
	dec = decrypt(enc_token)
	splitted_token = dec.split(b"|")
	assert len(splitted_token) == 2, "Please enter a token in the format encrypt(name|rm=int)"
	assert splitted_token[1].startswith(b"rm="), "no room is found"
	name, room = splitted_token[0], splitted_token[1][3:].decode()
	return name, int(room)

def menu():
	print("\n==================== DaVinci House - Entry ====================")
	print("1. Show Rooms")
	print("2. Get Room Access Token")
	print("3. Enter Room")
	print("4. Quit")

	choice = int(input("> "))

	return choice

def showRooms():
	print("\n*** Davinci House - Available Rooms ***")

	print("  Room 1: Monalisa Room")
	print("  Room 2: The Last Supper Room")
	print("  Room 3: Vitruvian Man Room")
	print("  Room 4: Salvator Mundi Room")
	print("  Room 1337: Secret Room")

def getRoomAccess():
	print("*** DaVinci House - Registration Gate ***")

	name = input("Name : ").encode()
	assert not b"davinci" in name.lower(), "No you're Not DaVinci, FRAUD!"

	room = int(input("Room number : "))
	assert 1 <= room <= 4, "Where you think can go ?"
	token = name + b"|" + b"rm=" + str(room).encode()

	return encrypt(token)

def enterRoom():
	print("\n*** Davinci House - Enter a Room ***")
	token = bytes.fromhex(input("Give your secret token (hex): "))
	name, room = parse(token)
	if name == b"DaVinci":
		if room == 1337:
			print("You made the impossible! Welcome to DaVinci's secret room, now take this ...")
			print(flag)
			print("And RUUN!")
			exit()
		else:
			print("Yeah Davinci can go anywhere in his house!\n")
	else:
		if room == 1337:
			print("Get lost!\n")
		else:
			print(f"Welcome to room {room}, enjoy !\n")


def welcome():
	welcome = "Welcome to"
	welcome += """
    ___               _               _
   /   \ __ _ /\   /\(_) _ __    ___ (_)   /\  /\ ___   _   _  ___   ___
  / /\ // _` |\ \ / /| || '_ \  / __|| |  / /_/ // _ \ | | | |/ __| / _ \\
 / /_//| (_| | \ V / | || | | || (__ | | / __  /| (_) || |_| |\__ \|  __/
/___,'  \__,_|  \_/  |_||_| |_| \___||_| \/ /_/  \___/  \__,_||___/ \___|

"""

	welcome += "\nDaVinci gives you the one and only opportunity to visit his house"
	welcome += "\nAnd discover his paintings. All the his work is divided into 5 rooms."
	welcome += "\nBut there is one room that he refused to open."

	print(welcome)

def main():
	welcome()


	for i in range(3):
		try:
			choice = menu()
			if choice == 1:
				showRooms()

			if choice == 2:
				enc_token = getRoomAccess()
				print("Here is your token, use it carefully:", enc_token)

			if choice == 3:
				enterRoom()

			if choice == 4:
				print("\nSee next time!")
				exit()
		except Exception as e:
			print(e)
			print("\nDon't cause problems. Bye!")
			exit()

if __name__ == "__main__":
	main()
```

We are supposed to bypass 2 checks, to enter room 1337, and be authenticated as DaVinci. The first one is a standard CBC bit flipping attack (change one character of the previous block to induce a change in the next block), to bypass the hardcoded check.

The second vulnerability of how to enter room 1337 is that when you first get the encryption of the first bit flipping payload, you can extend the payload even more and pad it smartly, such that you will be able to discard the unnecessary characters at the back in order to bypass the `len(splitted_token) == 2` check

```python
def getRoomAccess():
	print("*** DaVinci House - Registration Gate ***")

	name = input("Name : ").encode()
	assert not b"davinci" in name.lower(), "No you're Not DaVinci, FRAUD!"

	room = int(input("Room number : "))
	assert 1 <= room <= 4, "Where you think can go ?"
	token = name + b"|" + b"rm=" + str(room).encode()

	return encrypt(token)

def parse(enc_token):
	dec = decrypt(enc_token)
	splitted_token = dec.split(b"|")
	assert len(splitted_token) == 2, "Please enter a token in the format encrypt(name|rm=int)"
	assert splitted_token[1].startswith(b"rm="), "no room is found"
	name, room = splitted_token[0], splitted_token[1][3:].decode()
	return name, int(room)
```

By sending in

```python
name = b"A"*16+ b"EaVinci|rm=1337\x01" #to ensure correct padding
room = b'1'
```

It will give the encryption of

```
IV + 16 As + EaVinci|rm=1337|000000000000|rm=1
```

Then you can just trim off the unnecessary blocks and leave the desired block.

### Solver

```python
from pwn import *
from libnum import n2s, s2n

p = remote("20.65.65.163" ,1005)
text1 = b"A"*16+ b"EaVinci|rm=1337\x01"
#msg = IV + 16 As + EaVinci|rm=1337|000000000000|rm=1
p.recvuntil(b">")
p.sendline(b'2')
p.recvuntil(b"Name : ")
p.sendline(text1)
print("sent name")
p.sendlineafter(b"Room number : ", b"1")
print("Sent room")
line = p.recvline().strip().decode('utf-8')
token = line.split(": ")[1]
print(token)
# token = p.recvline().strip().decode('utf-8')
xor = ord('D') ^ ord('E')

token = token[32:-32] #remove the initial iv and the padding behind
token = hex(int(token[:2], 16) ^ xor)[2:]+token[2:]
print(token)
p.interactive()
```

## Challenge 3: Vault Keeper

### Description/Source

```python
from Crypto.Util.number import getPrime, long_to_bytes, inverse, getRandomNBitInteger
from secrets import flag

class RSA:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.e = 0x10001
        self.n = self.p * self.q
        self.d = inverse(self.e, (self.p-1)*(self.q-1))
        self.DaVinciSecretPass = b"Gimme The Ultimate Secret"

    def sign(self, data):
        return pow(data, self.d, self.n)

    def verify(self, data, sig):
        return self.sign(data) == sig

def welcome():
    welcom = ""
    welcom += """
 __   __   ______     __  __     __         ______      __  __     ______     ______     ______   ______
/\ \ / /  /\  __ \   /\ \/\ \   /\ \       /\__  _\    /\ \/ /    /\  ___\   /\  ___\   /\  == \ /\  == \
\ \ \\'/   \ \  __ \  \ \ \_\ \  \ \ \____  \/_/\ \/    \ \  _"-.  \ \  __\   \ \  __\   \ \  _-/ \ \  __<
 \ \__|    \ \_\ \_\  \ \_____\  \ \_____\    \ \_\     \ \_\ \_\  \ \_____\  \ \_____\  \ \_\    \ \_\ \_\
  \/_/      \/_/\/_/   \/_____/   \/_____/     \/_/      \/_/\/_/   \/_____/   \/_____/   \/_/     \/_/ /_/

    """
    welcom += "Leonardo is a trust paranoiac. He build a machine for authentication. He claims that is unhackable.\n"

    print(welcom)


def SignSecret(cipher):
    print("\n --------- Sign -------------")
    user_secret = int(input(" Enter a secret to sign (hex): "), 16)
    assert 0 < user_secret < cipher.n
    if cipher.DaVinciSecretPass in long_to_bytes(user_secret):
        print(" Get Lost!")
    else:
        print(" Signed secret :",hex(cipher.sign(user_secret)))

def VerifySecret(cipher):
    print("\n --------- Verify -------------")
    user_secret = int(input(" Enter a secret to verify (hex): "), 16)
    user_signature = int(input(" Enter a signature (hex): "), 16)
    vrf = cipher.verify(user_secret, user_signature)
    if vrf :
        if cipher.DaVinciSecretPass == long_to_bytes(user_secret):
            print(" You own it!")
            print(flag)
            print("RUN ...")
            exit()
        else:
            print(" Ok!")
    else:
        print(" Get Lost liar!")

def menu():
	print("\n ==================== Secret Keeper - Options ====================")
	print(" 1. Sign a secret")
	print(" 2. Verify a secret")
	print(" 3. Quit")

	choice = int(input("> "))

	return choice

def main():
    welcome()
    PainterVault = RSA()
    print(" N :", hex(PainterVault.n))
    print(" e :", hex(PainterVault.e))
    for i in range(4):
        try:
            choice = menu()
            if choice == 1:
                SignSecret(PainterVault)
            if choice == 2:
                VerifySecret(PainterVault)
            if choice == 3:
                print(" Bye Bye.")
                exit()
        except:
            print(' Do not miss behave! Bye.')
            exit()

if __name__ == "__main__":
    main()
```

We need to forge a message. We are allowed to encrypt anything other than the actual target message. This can be simply done due to the homomorphic multiplication property of RSA encryption. Since the target message in `long integer` is divisble by 2, get the encryption of the factors and multiply them together.

### Solver

```python
from pwn import *
from math import gcd
from libnum import s2n

target = s2n(b"Gimme The Ultimate Secret")
m1 = hex(target//2)[2:]
m2 = 2


p = remote("20.65.65.163",1006)
p.recvuntil(b'N :')
n = int(p.recvline().strip(), 16)
p.recvuntil(b'e :')
e = int(p.recvline().strip(), 16)
print("Got n:", n)
print("Got e:", e)

p.sendlineafter(b'>', b'1')
p.sendlineafter(b'secret to sign (hex):', str(m1).encode('utf-8'))
p.recvuntil(b'secret :')
c1 = int(p.recvline().strip()[2:], 16)

p.sendlineafter(b'>', b'1')
p.sendlineafter(b'secret to sign (hex):',str(m2).encode('utf-8'))
p.recvuntil(b'secret :')
c2 = int(p.recvline().strip()[2:], 16)

print("got c1:", c1)
print("got c2:", c2)

forged = hex((c1*c2) % n)[2:]
print(forged)
# p.interactive()
p.sendlineafter(b'>', b'2')
p.sendlineafter(b'verify (hex): ', (hex(target)[2:]).encode('utf-8'))
p.sendlineafter(b"signature (hex):", forged.encode('utf-8'))
p.interactive()

p.close()

```

### Flag

```
Securinets{Y0u_Sh0uld_n3veR_truSt_aNy0n3_f0r_y0uR_s3crEts}
```

## Challenge 4: CuliArts - El Brik

### Description/Source

```python
#! /usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secrets import FLAG, KEY
import os
KEY = os.urandom(16)
import socketserver

BANNER = """
  _____         __   _    ___         __
 / ___/ __ __  / /  (_)  / _ |  ____ / /_  ___
/ /__  / // / / /  / /  / __ | / __// __/ (_-<
\___/  \_,_/ /_/  /_/  /_/ |_|/_/   \__/ /___/

"""

MESSAGE = """Welcome,
Since Romdhan is next week, and most of you
will not be at home. So we decided to teach you
some culinary skills. Today's lesson is about EL BRIK
Today's special is Brik b Thon !"""



def menu():
	MENU  = "\n==================== El Menu ====================\n"
	MENU += "Select:\n"
	MENU += " 1. Brik 3adi\n"
	MENU += " 2. Brik Thon\n"
	MENU += " 3. Quit\n"
	MENU += "> "

	choice = input(MENU)
	return choice

BLOCK_SIZE = 16
aes_cipher = AES.new(KEY, AES.MODE_ECB)

def brik_3adi(cipher, msg):
	return cipher.encrypt(pad(bytes.fromhex(msg), BLOCK_SIZE)).hex()

def brik_thon(cipher, msg):
	return cipher.encrypt(pad(bytes.fromhex(msg) + FLAG, BLOCK_SIZE)).hex()

def main():
	print(BANNER)
	print(MESSAGE)
	while True:
		try:
			choice = menu()
			if choice == "1":
				inp = input("Make your brik (hex): ")
				brik = brik_3adi(aes_cipher, inp)
				print("Your brik is ready: ", brik)
				continue

			elif choice == "2":
				inp = input("Make your brik Thon (hex): ")
				brik = brik_thon(aes_cipher, inp)
				print("Your brik is ready: ", brik)
				continue

			elif choice == "3":
				print("Bye Bye.")
				exit(0)
			else:
				print("No we don't have that on the menu yet.")
		except :
			print("Don't miss behave. Bye")
			exit(0)

if __name__ == "__main__":
    main()


```

A very standard ECB byte by byte decryption due to deterministic encryption of ECB (ecb penguin hello). More details can be read up [here](https://node-security.com/posts/cryptography-byte-by-byte-ecb-decryption/). There are 2 main steps, a bit of fuzzing where you guess different payloads of different length to deduce the length of the flag, then after that pad it enough and extract the decryption byte by byte. A slight optimization can be made once you know that the format of the flag is `Securinets{[0-9a-f]*}`, instead of iterating through the whole ascii alphabet, you can iterate through hexadecimal alphabet.

### Solver

```python
from pwn import *

p = remote("20.65.65.163", 1007)
# p.interactive()

flag_length = 76

possible = "0123456789abcdef"
from tqdm import tqdm
test_length = 76
for i in range(len(flag), 76):
    fail = True
    for j in possible:
        try:
            char = (j).encode('utf-8')
            text = b"A"*(80 - i -1) + flag + char + b"A"*(80 - 1 - i)
            send_text = text.hex()
            p.sendlineafter(b">", b'2')
            p.sendlineafter(b"(hex): ", send_text.encode('utf-8'))

            code = p.recvline().strip().decode('utf-8').split(':')[1].strip()
            c1, c2 = code[:160], code[160:320]

            if c1 == c2:
                flag += char
                fail = False
                print(flag)
                break
        except Exception as e:
            print(e)
            p.close()
            exit()
    if fail:
        print("something wrong")
        print(flag)
        exit()
print("The flag is: " + flag)

```

### Flag

```python
Securinets{bc6f69e009df7a8330b2a185a5e36238f92700071b05303}
```

## Challenge 5: CuliArts - El Beyet

### Description/Source

```python
#! /usr/bin/python3

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secrets import FLAG

BLOCK_SIZE = 16
KEY = os.urandom(BLOCK_SIZE)
KEY = b"0123456789abcdef"
IV = KEY

BANNER = """
  _____         __   _    ___         __
 / ___/ __ __  / /  (_)  / _ |  ____ / /_  ___
/ /__  / // / / /  / /  / __ | / __// __/ (_-<
\___/  \_,_/ /_/  /_/  /_/ |_|/_/   \__/ /___/

"""

MESSAGE = """Welcome again,
Since Romdhan is next week, and most of you
will not be at home. So we decided to teach you
some culinary skills. Today's lesson is about the of "Tajmir El Beyet".
As you know a non fresh meal sucks. So, today's special is to know why?
"""

def menu():
	MENU  = "\n==================== El Menu ====================\n"
	MENU += "Select:\n"
	MENU += " 1. Jammer El Beyet\n"
	MENU += " 2. Quit\n"
	MENU += "> "

	choice = input(MENU)
	return choice

def encrypt(msg):
	aes_cipher = AES.new(KEY, AES.MODE_CBC, IV)
	return aes_cipher.encrypt(pad(msg, BLOCK_SIZE)).hex()

def jammer_elbeyet(data):
	aes_cipher = AES.new(KEY, AES.MODE_CBC, IV)
	return aes_cipher.decrypt(data)

def check_leak(msg):
	msg_blocks = [msg[i: i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
	flag_blocks = [FLAG[i: i+BLOCK_SIZE] for i in range(0, len(FLAG), BLOCK_SIZE)]
	for msg_block in msg_blocks:
		for flag_block in flag_blocks:
			if msg_block == flag_block:
				return True
	return False

enc_flag = encrypt(FLAG)

def main():
	print(BANNER)
	print(MESSAGE)
	print("\n\nThis is a very old meal, I cannot recognize its taste anymore:", enc_flag)

	try:
		choice = menu()
		if choice == "1":

			inp = bytes.fromhex(input("Old Meal (hex): "))
			assert len(inp) % 16 == 0 and len(inp) < 64

			beyet = jammer_elbeyet(inp)

			if check_leak(beyet):
				print(beyet.hex())
				print("No No Idi*t! You burned l3ché!")
			else:
				print("Mekla Mjamra: ", beyet.hex())

		elif choice == "2":
			print("Bye Bye.")

		else:
			print("No we don't have that on the menu yet.")

	except Exception as e:
		# print(e)
		print("Don't miss behave!")
		exit(0)

	finally:
		print("Bye!")

if __name__ == "__main__":
    main()
```

One of my favorite challenges from this CTF. The vulnerability is in the reuse of equivalent key and iv in CBC mode. Most of the inspiration was derived from this [post](https://crypto.stackexchange.com/questions/16161/problems-with-using-aes-key-as-iv-in-cbc-mode).

Once you understand how you can use 3 messages, to derive the key, you realise that you don't need to use a `0` to derive the key exactly, instead you can use bit flipping, to flip the existing bit in the cipher text block and then flip it back afterwards. Using the `0` just makes the key pop out instantly, but it is not necessary. As the comment on the post indicates, only 2 decryptions are required which is exactly what we have.

Note: this is super brief, but maybe I will beef up this explanation once I figure out how to render math in github (yay for new update)

### Solver

```python
from pwn import *
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES

p = remote("20.65.65.163", 1009)
p.recvuntil(b'taste anymore:')

cipher = p.recvline().strip().decode('utf-8')
print("given cipher:", cipher)
c0 = cipher[:30] + bytes([int(cipher[30:32],16)^1]).hex()
payload = c0*2

p.sendlineafter(b'>', b'1')
p.sendlineafter(b'(hex):', payload.encode('utf-8'))
p.recvuntil(b":")

d = p.recvline().strip().decode('utf-8')
d1 = d[:30] + bytes([int(d[30:32],16)^1]).hex()
d2 = d[32:62] + bytes([int(d[62:64],16)^1]).hex()
key = strxor(bytes.fromhex(d1),strxor(bytes.fromhex(d2),bytes.fromhex(c0)))

print("got key:", key)
decryption_algo = AES.new(key, AES.MODE_CBC, key)
print(decryption_algo.decrypt(bytes.fromhex(cipher)))

p.close()
```

### Flag

```python
Securinets{4bafa8b697d91fa93eddf516393591cb907a4ce7ba1fa31f342eaf5010a49381}
```

## Challenge 6: CuliArts - Chorba

### Description/Source

```python
#! /usr/bin/python3

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secrets import FLAG, KEY

BLOCK_SIZE = 16

BANNER = """
  _____         __   _    ___         __
 / ___/ __ __  / /  (_)  / _ |  ____ / /_  ___
/ /__  / // / / /  / /  / __ | / __// __/ (_-<
\___/  \_,_/ /_/  /_/  /_/ |_|/_/   \__/ /___/

"""

MESSAGE = """Welcome again,
Since Romdhan is next week, and most of you
will not be at home. So we decided to teach you
some culinary skills. Today's lesson is about El Mel7 F Chorba
As you know, after a long fasting day no body wants a salty meal, so
El Mel7 needs to be "9ad 9ad" !"""



def menu():
	MENU  = "\n==================== El Menu ====================\n"
	MENU += "Select:\n"
	MENU += " 1. Tfa9ed el mel7\n"
	MENU += " 2. Quit\n"
	MENU += "> "

	choice = input(MENU)
	return choice


def encrypt(msg):
	iv = os.urandom(BLOCK_SIZE)
	cipher = AES.new(KEY, AES.MODE_CBC, iv)

	return (iv + cipher.encrypt(pad(msg, BLOCK_SIZE))).hex()

def decrypt(data):
	iv = data[:BLOCK_SIZE]
	cipher = AES.new(KEY, AES.MODE_CBC, iv)

	return cipher.decrypt(data[BLOCK_SIZE:])

def tfa9ed_el_mel7(data):
	try:
		unpad(decrypt(data), BLOCK_SIZE)
		return "Delicious"
	except Exception as e:
		# print(e)
		return "Meeeel7aaa"


def main():
	print(BANNER)
	print(MESSAGE)
	print("\n\nBut first here is a perfect Chroba, try to get to this level:", encrypt(FLAG))
	while True:
		try:
			choice = menu()
			if choice == "1":
				inp = bytes.fromhex(input("Check Mel7 (hex): "))
				brik = tfa9ed_el_mel7(inp)
				print("layka_'s opinion:", brik)
				continue

			elif choice == "2":
				print("Bye Bye.")
				break

			else:
				print("No we don't have that on the menu yet.")
		except :
			print("Don't miss behave!")
			exit(0)

if __name__ == "__main__":
    main()
```

There is nothing more than I can say apart from standard CBC padding oracle attack. Just need to figure out the length of the pad. Scripting it is more the hard part, but the concept is exactly the same as every other CBC padding oracle attack.

### Solver

```python
from pwn import *

p = remote("20.65.65.163", 1008)

flag_length = 192-36

p.recvuntil(b"try to get to this level:")
cipher = p.recvline().strip().decode('utf-8')
iv = cipher[:32]
good = "Delicious"
bad = "Meeeel7aaa"


alphabet = "Securinets{0123456789abcdef}"
alphabet = "0123456789abcdef}"
def checkIfPaddingWrong(payload):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"hex):", payload.encode('utf-8'))
    p.recvuntil(b":")
    msg = p.recvline().strip().decode('utf-8')
    print("payload:", payload)
    return msg == bad

def findPadding(firstBlock, secondBlock):
    for i in range(0,len(firstBlock), 2):
        modifiedBlock = "a"*i + firstBlock[i:]
        if checkIfPaddingWrong(modifiedBlock + secondBlock):
            return i // 2


def findChar(firstBlock, secondBlock, padding):
    firstBlock = [int(firstBlock[i:i+2], 16) for i in range(0,len(firstBlock), 2)]
    test1 = firstBlock[:]
    for i in range(padding):
        test1[-i-1] ^= ((padding+1) ^ (padding))

    flag = ""
    while padding < 16:
        for i in alphabet:
            testBlock = test1[:]
            testBlock[-padding-1] ^= ((ord(i)) ^ (padding+1))
            payloadBlock = [bytes([j]) for j in testBlock]
            payloadBlock = (b"".join(payloadBlock)).hex()

            if not checkIfPaddingWrong(payloadBlock+secondBlock):
                flag = i + flag
                print("flag:", flag)
                padding += 1

                test1 = testBlock
                for i in range(padding):
                    test1[-i-1] ^= ((padding+1) ^ (padding))

                if padding > 16: return flag
                break
    return flag

curr_flag = ""
for i in range(128,len(cipher)-32,32):
    current_iv = cipher[i:i+32]
    current_block = cipher[i+32:i+64]
    padding= 0
    if i == 128:
        padding = 4
    flag_part = findChar(current_iv, current_block, padding)
    print("Got part:",flag_part)
    curr_flag += flag_part
    print(curr_flag)



p.close()

```

### Flag

```python
Securinets{6fd67919a7ed25ee95458e1bf1cc2b5eade32d5ff8fe7ac4c84c7f0d9ac8b6f7}
```

## Challenge 7: CuliArts - 3abi Kes Tey BeLouz

### Description/Source

```python
from ctypes import *
# from secrets import secret_menu
from libnum import n2s
import random

def pad(m, blocksize = 8):
	return m+bytes([blocksize-len(m)%blocksize])*(blocksize - len(m)%blocksize)

class KesTeyBeLouz:

	def __init__(self, key, blocksize = 8):
		self.key = key
		self.BLOCK_SIZE = blocksize

	def __t2bl(self, pt):
		assert len(pt) % self.BLOCK_SIZE == 0, "Data length is not in Block Size bound."

		blocks = [int.from_bytes(pt[i: i+self.BLOCK_SIZE // 2], "big") for i in range(0, len(pt), self.BLOCK_SIZE // 2)]
		return blocks

	def __bl2t(self, blocks):
		pt = b"".join(x.to_bytes(self.BLOCK_SIZE // 2, 'big') for x in blocks)

		assert len(pt) % self.BLOCK_SIZE == 0, "Data length is not in Block Size bound."
		return pt

	def __encrypt(self, block):
		y = c_uint32(block[0])
		z = c_uint32(block[1])
		sum = c_uint32(0)
		delta = 0x9e3779b9

		n = 32
		w = [0,0]

		while(n>0):
			sum.value += delta
			y.value += ( z.value << 4 ) + self.key[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + self.key[1]
			z.value += ( y.value << 4 ) + self.key[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + self.key[3]
			n -= 1

		w[0] = y.value
		w[1] = z.value
		return w

	def encrypt(self, pt):
		pt_blocks = self.__t2bl(pt)

		enc = []
		for i in range(0, len(pt_blocks), 2):
			ptblock = [pt_blocks[i], pt_blocks[i+1]]
			block_enc = self.__encrypt(ptblock)
			enc.append(block_enc[0])
			enc.append(block_enc[1])

		return self.__bl2t(enc)

def keygen(ind):
	key = [107, 215, 222, 69]
	r = random.randint(0, 255)
	key[ind] ^= r
	print(key)
	return bytes([ k for k in key])

Menu_lfa9r = [
	b"7th April 2022\n UniRestau: 3ejja Blech 3dham",
	b"8th April 2022\n UniRestau: Ma9rouna Bidha"
]

# secret = pad(secret_menu)
secret = pad(b"Securinets{sample_flag_that_is_quite_long}")
for i in range(4): # Multiple Encryption To Keep Me Away From Koujina :)
	key = keygen(i)
	cipher = KesTeyBeLouz(key)
	secret = cipher.encrypt(secret)


print(secret.hex())
# 2403b5bad11a6ca3b04a379b87630967c3f5c0526b5449b236f793ca225411087f7b0b1abcd2ce8f96ae6d843837b0aa30b48457d51ec6c0e062fd15bfa51b446dc6eb2219067c6f6dfe5489f38917e61acb56639f381eeac2b1d896a9c2bedef1149285af0d655e4f3e983f8dec9e2fac80066d29d5a69cfd2eee3946d906851d3f9dd2232c5714ad84c768ae01c80047bdd2eeaeb9dc25

```

The key is to figure out that this is using TEA Encryption. Given that the blocks are very small (4), and we know the format of the flag `Securinets{` and the fact that the alphabet is hexadecimal, it opens up a meet in the middle attack.

Since we know the some 8 bytes somewhere in the message starts with Securine, so I can build a dictionary of 16^4 \* 256 of possible encryptions of the first two rounds and do meet in the middle for the remaining 2 rounds, which in 6 minutes was done. (Had to go through all possible placements of the flag in the long message)
The decryption routine was just taken from online after a quick google search of `python tea encryption`

### Solver

```python
from libnum import s2n, n2s
from ctypes import *
from tqdm import tqdm

def encipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0)
    delta = 0x9e3779b9
    n = 32
    w = [0,0]

    while(n>0):
        sum.value += delta
        y.value += ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        z.value += ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w

def decipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0xc6ef3720)
    delta = 0x9e3779b9
    n = 32
    w = [0,0]

    while(n>0):
        z.value -= ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        y.value -= ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        sum.value -= delta
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w


def arrBytes(arr):
    res = b""
    for i in arr: res += n2s(i)
    return res.hex()

def test():
    v = [s2n(b"Secu"), s2n(b"rine")]
    k1 = [1, 215, 222, 69]
    k2 = [107,1, 222, 69]
    k3 = [107, 215, 1, 69]
    k4 = [107, 215, 222, 1]
    v = encipher(v, k1)
    v = encipher(v, k2)
    v = encipher(v, k3)
    v = encipher(v, k4)

    print("Finished Encryption v:", arrBytes(v), arrBytes(v).hex())

    v = decipher(v, k4)
    v = decipher(v, k3)
    v = decipher(v, k2)
    v = decipher(v, k1)

    print("Finished Decryption v:", arrBytes(v))
    exit()

def decryptAll(ct):
    k1 = "75d7de45"
    k2 = "6bf4de45"
    k1 = [int(k1[i:i+2],16) for i in range(0,len(k1),2)]
    k2 = [int(k2[i:i+2],16) for i in range(0,len(k2),2)]
    k3 = [107, 215, 163, 69]
    k4 = [107, 215, 222, 214]
    res = b""
    for i in range(0,len(ct),2):
        block = ct[i:i+2]
        block = decipher(block, k4)
        block = decipher(block, k3)
        block = decipher(block, k2)
        block = decipher(block, k1)
        res += bytes.fromhex(arrBytes(block))
    print(res)

    exit()


if __name__ == "__main__":
    d = {}
    cipher = "2403b5bad11a6ca3b04a379b87630967c3f5c0526b5449b236f793ca225411087f7b0b1abcd2ce8f96ae6d843837b0aa30b48457d51ec6c0e062fd15bfa51b446dc6eb2219067c6f6dfe5489f38917e61acb56639f381eeac2b1d896a9c2bedef1149285af0d655e4f3e983f8dec9e2fac80066d29d5a69cfd2eee3946d906851d3f9dd2232c5714ad84c768ae01c80047bdd2eeaeb9dc25"
    blocks = [int(cipher[i:i+8],16) for i in range(0,len(cipher), 8)]

    key = [107, 215, 222, 69]
    original = b"Securinets{"
    decryptAll(blocks)

    vs = []
    for i in range(4):
        vs.append([s2n(original[i:i+4]), s2n(original[i+4:i+8])])


    for v in vs:
        for k in tqdm(range(0,len(blocks),2)):
            d = {}
            block = blocks[k:k+2]
            for i in range(256):
                for j in range(256):
                    k1 = bytes([i,215,222,69])
                    k2 = bytes([107,j,222,69])

                    enc = encipher(v,k1)
                    enc = encipher(enc, k2)
                    entry = arrBytes(enc)
                    if entry not in d:
                        d[entry] = [k1,k2]

            # print("Done building lookup table")
            for i in range(256):
                for j in range(256):
                    k3 = [107,215,i,69]
                    k4 = [107,215,222,j]
                    dec = decipher(block, k4)
                    dec = decipher(dec, k3)
                    entry = arrBytes(dec)
                    if entry in d:
                        print("got something?")

                        for i in d[entry]:
                            print(i.hex())
                        print(k3,k4)
                        decryptAll(blocks)



    # enc = encipher(v,key)
    # print( get_dec(decipher(enc,key)))
```

### Flag

```python
'9th April 2022\n Romdhaaaan w chi5aat a la mizon\n Ochrob Teyek hani jeyek!\nFlag leaked: Securinets{MITM_F0r_M3eT_1n_7He_M1dDL3_0f_TEA!_W3ll_D0n3!}\x07\x07\x07\x07\x07\x07\x07'
```

### Side Note:

The intended solve for the challenge was to figure out that the menu was starting with consecutive dates and use that to predict, but I think my method is a bit lcenaer :p.

## Challenge 8: RNGs goes PRRRNG

### Description/Source

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
from secrets import flag

BLOCK_SIZE = 16

class PRNG(object):
	def __init__(self, seed):
		self.seed = seed

	@staticmethod
	def rotl(x, k):
		return ((x << k) & 0xffffffffffffffff) | (x >> 64 - k)

	def next(self):
		s0 = self.seed[0]
		s1 = self.seed[1]

		result = (s0 + s1) & 0xffffffffffffffff

		s1 ^= s0

		self.seed[0] = self.rotl(s0, 55) ^ s1 ^ ((s1 << 14) & 0xffffffffffffffff)
		self.seed[1] = self.rotl(s1, 36)
		return (result)

key = urandom(BLOCK_SIZE)

cipher = AES.new(key, AES.MODE_ECB)
flag_enc = cipher.encrypt(pad(flag, BLOCK_SIZE)).hex()

#print(key.hex())
print(f"{flag_enc=}")

seed1 = bytes_to_long(key[: BLOCK_SIZE//2])
seed2 = bytes_to_long(key[BLOCK_SIZE//2: ])

myRNG = PRNG([seed1, seed2])
key2 = bytes.fromhex(hex(myRNG.next())[2:] + hex(myRNG.next())[2:])

msg = b"Forward Secrecy is The Real Deal! No 0ne will get our secret now"
cipher2 = AES.new(key2, AES.MODE_ECB )
msg_enc = cipher.encrypt(pad(msg, BLOCK_SIZE)).hex()
print(f"key2 ='{key2.hex()}'")
print(f"{msg_enc=}")


"""
flag_enc='4f0b8bafbb69a85e4d0ead119122cf857e9ee40a9110ecd340eefe68aafdeb0607ea3c160bcc2097df6edc916f485f0626e665634dba2f51a2b6bc10a648e901'
key2 ='bef4470a03d7db5c93371388525e2425'
msg_enc='d3c9bfd6fe103fdb514513fc34ed20eab487adeac810b1781f0d4c6eb260e69eeec16db7a5804566eb4f97960557c8edb41c319b2fce0e1612151dfa482dcd03e111cfc3153dcb6d2c6b8764fcbfeb43'
"""

```

Googling a bit of the encryption code led me to the xoroshiro rng, which the cracking code can be found [online](https://github.com/lemire/crackingxoroshiro128plus).

```python
#!/usr/bin/python
# credit: achan001
# usage : python xoroshiftall.py 0 0xdeadbeef
import sys, z3
bit64 = 0xffffffffffffffff

def LShL(x, n): return (x << n) & bit64

def xo128(x, y, LShR = lambda x,i: x>>i):
    y ^= x
    return y ^ LShL(y, 14) ^ (LShL(x,55)|LShR(x,9)), (LShL(y,36)|LShR(y,28))

a = 13759700869863431004
b = 10607968923512874021


x0, y0 = z3.BitVecs('x0 y0', 64)
x, y = x0, y0
s = z3.SimpleSolver()



for v in [a,b]:
    n = v
    s.add((x + y) & bit64 == n)
    x, y = xo128(x, y, z3.LShR)

for i in range(1, sys.maxsize):
    print('\n#%d = %s' % (i, s.check()))
    if s.check().r != 1: break  # quit if failed
    soln = s.model()
    x, y = (soln[i].as_long() for i in (x0,y0))
    print('state =', hex(x), hex(y))
    for j in range(10):         # show predictions
        print(hex((x+y) & bit64))
        x, y = xo128(x, y)
    s.add( z3.Or(x0 != soln[x0], y0 != soln[y0]) )
```

After deriving the seed, the decryption routine is quite trivial

### Solver

```python
seed1 = "0X979FFBE3A0F6985E"
seed2 = "0X44370726A6FE25A2"

flag_enc='4f0b8bafbb69a85e4d0ead119122cf857e9ee40a9110ecd340eefe68aafdeb0607ea3c160bcc2097df6edc916f485f0626e665634dba2f51a2b6bc10a648e901'
key2 ='bef4470a03d7db5c93371388525e2425'
msg_enc='d3c9bfd6fe103fdb514513fc34ed20eab487adeac810b1781f0d4c6eb260e69eeec16db7a5804566eb4f97960557c8edb41c319b2fce0e1612151dfa482dcd03e111cfc3153dcb6d2c6b8764fcbfeb43'



from Crypto.Cipher import AES

s1,s2 = 0xc32921be5cad2cc6, 0xfbcb254ba72aae96
s3,s4 = 0xf04a28c23bc308cd, 0xceaa1e47c814d28f

# from libnum import n2s
from Crypto.Util.number import *

for a,b in [(s1,s2), (s3,s4)]:
    key = long_to_bytes(a) + long_to_bytes(b)
    cipher = AES.new(key, AES.MODE_ECB)
    print(cipher.decrypt(bytes.fromhex(flag_enc)))


    cipher2 = AES.new(key, AES.MODE_ECB )
    print(cipher2.decrypt(bytes.fromhex(msg_enc)))
```

### Flag

```
Securinets{___PRNGs_4r3_sh1t_Try_t0_s0m3th1ng_Str0ng3r!!___}
```

## Challenge 9: CuliArts - Mlewi

### Description/Source

```python
import random
from PIL import Image
from secrets import flag

def r2p(n):
	return n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff

def byte2bin(m):
	b = [bin(byte)[2:].zfill(8) for byte in m]
	b = [int(bit) for _ in b for bit in _]
	return b

flag_bits = byte2bin(flag)

width, height = 650, 2

img = Image.new( 'RGBA', (width,height), "white")
pixels = img.load()

nums = []
for _h in range(height):
	for _w in range(width):
		xkey = random.getrandbits(32)


		xr, xg, xb, xa = r2p(xkey)
		pixels[_w,_h] = ((_w & 0xff) ^ xr, _h ^ xg, ((_w*_h) & 0xff) ^ xb, ((_w+_h) & 0xff) ^ xa )

		if _h & 1 == 1:
			p_ind = _w % 4
			pixel = list(pixels[_w,_h])

			pixel[p_ind] ^= flag_bits[_w % len(flag_bits)]
			pixels[_w,_h] = tuple(pixel)
			print(xr,xg,xb,xa, xkey, flag_bits[_w % len(flag_bits)])
		else:
			pass
img.save("flag.enc.png", "PNG")
```

Again, a very similar PRNG cracking, this time, its the default python implementation. We are given a 2 x 650 image. Which means we know the first 650 values of the RNG, so we can just use that to predict the next 650 rng numbers using MersenneTwister predictor Library --> decryption!

### Solver

```python
from PIL import Image
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()

def r2p(n):
	return n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff

width, height = 650, 2
img = Image.open('flag.enc.png')
pixels = img.load()
flag_xored = []
arr = []


predictor = MT19937Predictor()
for i in range(650):
    px = list(pixels[i,0])

    px[0] ^= ( i & 0xff)
    px[3] ^= ( i & 0xff)
    binNumber = ""

    for num in px:
        binNumber  = bin(num)[2:].zfill(8) + binNumber
    binNumber = int(binNumber, 2)
    if i  < 624:
        predictor.setrandbits(binNumber, 32)
    else:
        assert predictor.getrandbits(32) == binNumber


nextNums = [predictor.getrandbits(32) for _ in range(650)]

for i in range(width):
    rand = r2p(nextNums[i])
    p_ind = i % 4
    if p_ind == 0:
        relevant = pixels[i,1][p_ind] ^ ( i & 0xff) ^ rand[p_ind]
    elif p_ind == 1:
        relevant = pixels[i,1][p_ind] ^ 1 ^ rand[p_ind]
    elif p_ind == 2:
        relevant = pixels[i,1][p_ind] ^ ( i & 0xff) ^ rand[p_ind]
    elif p_ind == 3:
        relevant = pixels[i,1][p_ind] ^ ((i+1) & 0xff) ^ rand[p_ind]
    assert  0<=relevant <= 255

    arr.append(relevant)

def byte2bin(m):
	b = [bin(byte)[2:].zfill(8) for byte in m]
	b = [int(bit) for _ in b for bit in _]
	return b

from libnum import n2s
def bin2byte(arr):
    return n2s(int(''.join(list(map(str, arr))),2))

for i in range(2,40,8):
    print(bin2byte(arr[:-i]))

```

### Flag

```
Securinets{_M3r5enNe_kN0ws_H0w_T0_RoOll_Ml3w1!W4iT_175_n0t_S0s_N4m3_It's_Mersenne_Twister!!_}
```

## Challenge 10: CuliArts - Tchanchina

### Description/Source

We are given a remote to connect to where we are given 30 random questions and we have to give an answer YES/NO. There is a delay in timing depending on your answer so it is a basic kind of side channel attack. If the response takes more than 1 second, your guess is correct, otherwise it is wrong. The entire challenge can be solved in 2 rounds, once to get all the answers / calibrate, the second round to give the correct answers

### Solver

```python
import time
from pwn import *

p = remote("20.203.26.7", 10010)

p.recvuntil(b'EGIN QUIZ')
p.recvline()
p.recvline()

d = {}
y = b'Yes'
n = b'No'
p.recvuntil(b'.')

def getQuestion(i):
    qn = p.recvuntil(b'>')
    t1 = time.time()
    p.sendline(y)
    p.recvuntil(b'.')
    t2 = time.time()
    if int(t2-t1) > 1:
        d[qn] = y
    else:
        d[qn] = n
    print(f"Qn {i} {qn}: {d[qn]}")

def getAnswers(i):
    qn = p.recvuntil(b'>')
    p.sendline(d[qn])
    print(f"Qn {i}, Sending ans to {qn}: {d[qn]}")
    if i != 30:
        p.recvuntil(b'.')

for i in range(30):
    getQuestion(i+1)


for i in range(30):
    getAnswers(i+1)
p.interactive()
```

### Flag

```python
Securinets{T1K_T0K_0uR_Ch3F_h1s_T1m3_1s_V4lU4bL3_AnD_y0u_w4st3_1t!_Wh4At_3VaH_Y0u_go0Ot_It}
```

## Challenge 11: CuliArts - El Beyet^2

### Description/Source

```python
from Crypto.Util.number import *
from secrets import flag, N, e

def encrypt(m, N, e):

	assert type(m) == int

	for fi in bin(m)[2:]:
		x = getPrime(128)

		yield pow(pow(2, x + int(fi)) * pow(x + int(fi), 2), e, N)

m = bytes_to_long(flag)

ENC_B = []

for benc in encrypt(m, N, e):
	ENC_B.append(benc)

# I think that's all you need
print(f"{N = }")
print(f"{ENC_B = }")
```

This one stumped me for quite a while, but eventually google turned up Goldwasser–Micali cryptosystem which basically is similar to this but encrypts one bit at a time of a number. However, the hardness of decryption is that the computation of the Jacobi Symbol is hard to do for `N` if the prime factorisation is not known, however since `N` in this case is prime, it is practically instant.

### Solver

```python
N = ...
ENC_B = [...]

msg = ""
for i in ENC_B:
    if jacobi_symbol(i,N) == 1:
        msg += "1"
    else:
        msg += "0"
flag = n2s(int(msg,2))
print(flag)


```

### Flag

```
Securinets{__Do_N0t_Soph1stcate_Th1ngs_4nD_D0_n0T_r0ll_y0uR_oWn_Crypto__}
```

## Challenge 12: El Beyet^3

### Description/Source

A standard RSA parity oracle, see [here](https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-3/) for more details. But basically each message allows you to narrow down the range of possible messages by 1/2, so you need minimum `n` queries where `n` is the number of bits in modulus. Make sure to craft your messages accordingly to the formula given in the link.

### Solver

````python

```python
from pwn import *
from libnum import n2s
import math

p = remote("20.74.156.148", 10011)
p.recvuntil(b"N = ")
N = int(p.recvline().decode('utf-8'), 16)
p.recvuntil(b"e = ")
e = int(p.recvline().decode('utf-8'), 16)

p.recvuntil(b"pow(flag, e, N)): ")
ct = int(p.recvline().decode('utf-8'), 16)
print("Received N: ", N)
print("Received e: ", e)
print("Received ct: ", ct)

def getParity(inp):
    inp = hex(ct*pow(inp,e,N) % N).encode('utf-8')
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"(hex):", inp)
    p.recvuntil(b"Some leftovers for you ( pow(c,d,N)%2 ):")
    res = int(p.recvline().decode('utf-8'))
    return res

lo,hi = 0,N
num = 2
mid = N//2
while lo < hi:
    res = getParity(num)
    num <<=1

    if res == 0:
        hi = (hi + lo)//2
    elif res == 1:
        lo = (lo + hi)//2
    else:
        print("Unsuccessfull")
        break

    print ('Remaining bits:', int(math.log(hi - lo, 2)))
print("Flag : ", n2s(lo))
p.interactive()

````

### Flag

```
Securinets{__L$Be_RSA_0r4cl3__}
```

## Challenge 13: Polllis

### Description/Source

```python
from Crypto.Util.number import *
from secrets import n, m, flag

assert isPrime(n**11 + 2022) and isPrime(m**11 + 2022)

p, q = n**11 + 2022, m**11 + 2022

N = p*q
e = 65537

m = bytes_to_long(flag)
c = pow(m, e, N)

print(f"{N = }")
print(f"{e = }")
print(f"{c = }")

```

We can estimate the primes `p` and `q` by taking them`p*q ~= floor(N^(1/11))`, because `2022` is quite small in comparison to the numbers `n` and `m`. To factorize the resulting number, I just left it in `alpertron` and compared each factor with the original equation to see if it matched, if it did, it was one of the primes. After that its standard rsa decryption.

Note: I got stuck on this for super long trying to construct a matrix to do LLL (got thrown off by the name of the challenge)

### Solver

```python
import gmpy2
from libnum import n2s
gmpy2.get_context().precision=5000

N = 264543366172178486135735045675295527742138265688734829408412179868516892019400034745293257399379954540941287677167223337829887277113850612720554965166962903797358119769491760172277972574914454074587227341395416822005042709049463893451369533244833554475535782617661994511679918415677704319932391196548757352124045934907411420934329065106986203693187967253483421308983980531732276221798222499366361245399850290106185099335870720300119577516607936434135750682706353298469528885268234786589663881482856648170213168527750825906487371009054725403867346024265274271306450508629470564015839645566073369298864052467613212869470024254063338072145608313481963867989736811997868812223126537583241439298339875625125329998442223788118927294707708108124898786714141392295229386619550042818417875339868045833447220428067769206114263761933841009621570844724022343989437913944567435186067321865400121050211923284157288057358507321801448076376493747286468060624316741289109286410650003288730193034485305251344937906252970807182621139677727596063878932400992263864602927097498200760311597972305878530686865080962331543023693739086391314106122270721110690025803907018003597564936933551927438642589435421965504007291841299344483589329440455026611483691
e = 65537
c = 234293751653853182488093069144740036156636091652670339596098794939206449405157291815884292406845194726915539836552620851473799295792168562704822107101472473002339536865603473777201890419362244327428636716908796645583129834720361243267897146655078599820769806944289648559523220863204732548066024418998841592423319875408206353314570502447564242512949800127114504067062170232416299882180377382945740991994755901832425600220195295494021153535810698690119695415706400238321628076698726496437938712787449183394228969110856757177436849044760472244537014834443076915612859585742588549545663716353734294754812276507384407287971817158902924300518762267586875482014905173543269074499546245970652709145102606853237434695432221204562266366919139354404345626638496989688827125768321650193792486761701223743302299720832421880935534181398240126531313858069206807542409090884768524184621398545816703465845296432304985021404529847075428550398047629310657794488315523086086262816451501162979482191026729958571496266426196067111000041033599548601707507925370033761329616435210192810051204857622919689120050613784772566046326380407404353590272872860619261361845400358264966979517934890139167023954970612269849822860778074437478545239226025236712708601


"""
p, q = n**11 + 2022, m**11 + 2022

N = (p+p')^11 * (q + q')^11
n = (p+p')*(q+q')
"""
pq = int(gmpy2.root(N,11))

factors = []
with open("out.txt", "r") as f:
    for i in f.readlines():
        if N%(pow(int(i),11) + 2022)== 0:
            factors.append(int(i))
m,n = factors
p,q = pow(m,11)+2022, pow(n,11)+2022

phi = (p-1)*(q-1)
d = int(gmpy2.invert(e, phi))

print(n2s(pow(c,d,N)))
```

### Flag

```
Securinets{i don't know what to say! i hate those primes}
```
