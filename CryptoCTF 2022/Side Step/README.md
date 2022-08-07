## Side Step (Medium) - 28 solves

### Description/Source

```py
#!/usr/bin/env python3

from Crypto.Util.number import *
import random, sys
from flag import flag

def pow_d(g, e, n):
	t, r = 0, 1
	for _ in bin(e)[2:]:
		if r == 4: t += 1
		r = pow(r, 2, n)
		if _ == '1': r = r * g % n
	return t, r

def ts(m, p):
	m = m % p
	return pow(m, (p - 1) // 2, p) == 1

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
	pr(border, "Hi all cryptographers! Welcome to the Sidestep task, we do powing!!!", border)
	pr(border, "You should solve a DLP challenge in some special way to get the flag", border)

	p = 2 ** 1024 - 2 ** 234 - 2 ** 267 - 2 ** 291 - 2 ** 403 - 1
	s = random.randint(2, (p - 1) // 2)

	while True:
		pr("| Options: \n|\t[T]ry the magic machine \n|\t[Q]uit")
		ans = sc().lower()

		if ans == 't':
			pr(border, "please send your desired integer: ")
			g = sc()
			try:
				g = int(g)
			except:
				die(border, "The given input is not integer!")
			if ts(g, p):
				t, r = pow_d(g, s, p)
				if r == 4:
					die(border, f'Great! you got the flag: {flag}')
				else:
					pr(border, f"t, r = {t, r}")
			else:
				pr(border, "The given base is NOT valid!!!")
		elif ans == 'q':
			die(border, "Quitting ...")
		else:
			die(border, "Bye bye ...")

if __name__ == "__main__":
	main()
```

### Solver

```python
from telnetlib import Telnet

host, port = "01.cr.yp.toc.tf", 17331
LOCAL = False
# p = remote(host, port)
p = Telnet(host, str(port))
def sendBase(g):
    p.read_until(b'|\t[Q]uit\n')
    p.write(b'T' + b'\n')
    p.read_until(b'| please send your desired integer:')
    p.write(str(g).encode() + b'\n')
    line = p.read_until(b'| t, r = ', timeout=3)
    if b'Great' in line:
        print(line)
        return True, True
    t,r = eval(p.read_until(b')').strip().decode('utf-8'))
    return t,r


import random
random.seed(0)
prime = 2 ** 1024 - 2 ** 234 - 2 ** 267 - 2 ** 291 - 2 ** 403 - 1
s = random.randint(2, (prime - 1) // 2)
print("Secret:", s)
Zp = Zmod(prime)

def testing(g, p):
    if not LOCAL:
        return sendBase(g)

    def pow_d(g, e, n):
        t, r = 0, 1
        for _ in bin(e)[2:]:
            if r == 4: t += 1
            r = pow(r, 2, n)
            if _ == '1': r = r * g % n
        return t, r

    def ts(m, p):
        m = m % p
        return pow(m, (p - 1) // 2, p) == 1

    if ts(g, p):
        t, r = pow_d(g, s, p)
        if r == 4:
            print("Solved")
            return True, True
        else:
            return t,r
    else:
        print("Failed quad residue")


def check(root):
    print("Root Bits check:", ZZ(root).nbits() , root)
    ans = Zp(2).nth_root(root)
    t,r = testing(ans, prime)

    # means solved
    if t == True and r == True:
        return True

    # increase bit size
    root <<= 1

    # if 4 does not appear, means the first bit needs to be set
    if t == 0:
        root |= 1

    return root

def refinedCheck(root):
    print("Root Bits Refined check:", ZZ(root).nbits())
    print("Root:", root)
    ans = Zp(4).nth_root(root)
    t,r = testing(ans, prime)

    if t == True and r == True:
        return True

    return False


def solve():
    s_high = 1
    for _ in range(1024):
        res = check(s_high)
        if res == True:
            print("Res:", res)
            print("Solved")
            return
        s_high = res

    for i in range(20):
        if refinedCheck(s_high):
            print("exponent:", s_high)
            return
        s_high >>= 1

```

### Flag

```
CCTF{h0W_iZ_h4rD_D15crEt3_lO9ar!Thm_c0nJec7ur3?!}
```

### References

- https://zhuanlan.zhihu.com/p/546270351
- [Telnet Documentation](https://docs.python.org/3/library/telnetlib.html)
