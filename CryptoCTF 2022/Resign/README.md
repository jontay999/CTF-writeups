## Resign (Medium) - 35 solves

### Description/Source

```py
#!/usr/bin/env python3

from Crypto.Util.number import *
from hashlib import sha1
import sys
from flag import flag

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.readline().strip()

def main():
	border = "|"
	pr(border*72)
	pr(border, " Hi, Try to guess our RSA private key to sign my message, talented  ", border)
	pr(border, " hackers like you ;) are able to do it, they are *Super Guesser* :) ", border)
	pr(border*72)

	p, q = [getPrime(1024) for _ in '__']
	n, e = p * q, 65537
	phi = (p - 1) * (q - 1)
	d = inverse(e, phi)

	MSG = b'::. Can you forge any signature? .::'
	h = bytes_to_long(sha1(MSG).digest())
	SIGN = pow(h, d, n)

	while True:
		pr("| Options: \n|\t[G]uess the secret key \n|\t[R]eveal the parameters \n|\t[S]ign the message \n|\t[P]rint the signature \n|\t[Q]uit")
		ans = sc().lower()
		if ans == 'g':
			pr(border, f"please send the RSA public exponent and PARAMS p, q separated by comma like e, p, q: ")
			PARAMS = sc()
			try:
				E, P, Q = [int(_) for _ in PARAMS.split(',')]
				if P.bit_length() == Q.bit_length() == 1024 and P != Q:
					N = P * Q
					PHI = (P - 1) * (Q - 1)
					D = inverse(E, PHI)
					if pow(h, D, N) == SIGN:
						e, n, d = E, N, D
						pr(border, 'Great guess, now you are able to sign any message!!!')
					else:
						pr(border, 'Your RSA parameters are not correct!!')
				else: raise Exception('Invalid RSA parameters!!')
			except: pr(border, "Something went wrong!!")
		elif ans == 'r':
			pr(border, f'e = {e}')
			pr(border, f'n = {n}')
		elif ans == "p":
			pr(border, f'SIGN = {SIGN}')
		elif ans == 's':
			pr(border, "Please send the signature of this message: ")
			pr(border, f"MSG = {MSG[4:-4]}")
			sgn = sc()
			try:
				sgn = int(sgn)
				_continue = True
			except:
				pr(border, "Something went wrong!!")
				_continue = False
			if _continue:
				_MSG = MSG[4:-4]
				_h = bytes_to_long(sha1(_MSG).digest())
				if pow(sgn, e, n) == _h:
					die(border, "Congrats! your got the flag: " + flag)
				else:
					pr(border, "Sorry, your signature is not correct!")
		elif ans == 'q': die("Quitting ...")
		else: die("Bye bye ...")

if __name__ == "__main__": main()
```

The key of the challenge is that solving for 1 set of constants of `a` and `b` solves for every set of constant, so don't need to sweat the choice of `a` and `b`, just assuming one of them is 1 and do some basic modulo equation stuff to solve the other constant.

For solving the $(ax + by) \pmod{q} = 0$ equation, the key is just to assume any value of the constrained value, e.g. if $x$ has to be 12 bit, just set $x$ to be `1<<10 + 1` and then solve the equation for the remaining vairable. Similar to above, solving 1 equation solves every equation so don't sweat the choice of either $x$ or $y$

Just solve 5 of these and the solution pops out

### Solver

```python

q = 325729570283337093050350174899088694381
r = 312556704284690216591398346568857384535
s = 56148108437440312246654313011839929156

x = 1<<26 +1
print(x.bit_length())
# assert y.bit_length() == 12

a = 1
b = (-r * pow(s,-1,q)) % q
assert (a*r + b*s) % q == 0

y = ((-a*x) * pow(b,-1,q)) % q

assert (a*x + b*y) % q == 0
print(x,y)

```

### Flag

```
CCTF{f1nDin9_In7Eg3R_50Lut1Ons_iZ_in73rEStIn9!}
```

![solve](./solve.png)
