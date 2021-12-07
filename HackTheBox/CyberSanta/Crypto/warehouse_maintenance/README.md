# Cyber Santa 2021 – Warehouse Maintenance

- **Category:** Crypto Day 5
- **Points:** 325
- **Difficulty:** ★★☆☆

## Challenge

> Elves are out of control! They have compromised the database of Santa's warehouse. We have revealed the endpoint and we need to find a way to execute commands in the database. Unfortunately, every command needs to be signed by an Elf named Frost. Can you find a way in?

We are given a python script that shows a connection to a mySQL instance. SQL Queries are hashed using SHA512 and the command will only be executed if it matches <em>Mr Frost's</em> signature.

```
salt = os.urandom(randint(8,100))

def create_sample_signature():
	dt = open('sample','rb').read()
	h = hashlib.sha512( salt + dt ).hexdigest()

	return dt.hex(), h

def check_signature(dt, h):
	dt = bytes.fromhex(dt)

	if hashlib.sha512( salt + dt ).hexdigest() == h:
		return True
```

There is a random salt that can be of length 8 to 100 which means that it cannot be brute forced.

We are also given a sample script to work with which looks like

```
USE xmas_warehouse;
#Make sure to delete Santa from users. Now Elves are in charge.
```

## Solution

SHA512 cannot be broken, but it is still vulnerable to hash length extension attacks as a random salt is prepended to the SQL query before hashing. Even if the secret is unknown, a valid hash can still be generated if the key length is known, by picking up where the hashing algorithm left off based on a certain block size. Read more about it at https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks.

The new hash can be crafted using a python library called [hashpumpy](https://github.com/bwall/HashPump).
Using this library we brute force the secret length until we get a successful message.

```
from hashpumpy import hashpump
from pwn import *

p = remote("178.128.35.132", 32288)
print(p.recvuntil(b">"))
hexdigest = "b9513efee9fd825dcefb18711db5dd1d2e3735c0729e43aeba33db3d5f26e2f44070eb699100fea02847fca032dc99bc06d4656617db1c01691664000d933738"
knowndata = b"USE xmas_warehouse;\n#Make sure to delete Santa from users. Now Elves are in charge."
correct_key_length = 90
for key_length in range(8,101):
	p.send(b'2')
	print(p.recvuntil(b">"))
	data_to_add = b"SHOW TABLES;"
	signature, script = hashpump(hexdigest, knowndata, data_to_add, key_length)
	d = {"script": script.hex(), "signature": signature}
	payload = bytes(json.dumps(d), 'utf-8')
	p.send(payload)
	result = p.recvuntil(b'>')
	if(b' Are you sure mister Frost signed this?' in result):
		print("Wrong key length", key_length)
	else:
		print("Got it", key_length)
		print(result)
		correct_key_length = key_length
```

After we get the length of the salt, we try a few queries like `SHOW TABLES` which gives us `users` and `materials` tables.

After running `SELECT * from materials` we get the flag.

```
b" (1, 'wood', 124)(2, 'sugar', 352)(3, 'love', 999)(4, 'glass', 719)(5, 'paint', 78)(6, 'cards', 1205)(7, 'boards', 1853)(8, 'HTB{h45hpump_15_50_c001_h0h0h0}', 1337)\n"
```

## Thoughts

- Honestly I did not manage to solve it within the time frame. I got 95% of the code but for some reason it didn't work. The problem with my code was that originally I set the sample script to be in hex rather than in bytes which was causing the hashpumpy to give me its signature in a mixture of bytes and hex. After the competition, I amended the known_data to be in bytes and it worked!
- Was a good crypto challenge, and introduced me to the idea that the SHA encryption algorithms can still have vulnerabilities.
