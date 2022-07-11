# VSCTF 2022 – Crypto Challenge

## Secure Grading System (21 solves): 487 points

### Description/Source

```python
import string
import sys
import ecdsa
import hashlib
import random
from time import time
from base64 import b64encode
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, size
from secret import FLAG, get_report_content


'''
Grading system documentation (for internal use ONLY)

1. The school's grader team consists of 3 tutors and a professor.
2. To submit the final report, student first needs to pass Proof of Work to show they are not robots.
3. The student will sign their report (in text format) with their name and send it to the professor.
Professor will verify the signature and make sure the student is THE real student.
4. The student will then send 3 copies of their report to each of the tutors for marking.
Finally student will receive their scoring.
5. REDACTED
6. Combining these public-key cryptosystems mentioned above, no way the system will have any vulnerability...
Secure data transmission for the win! NO CHEATING IS ALLOWED IN OUR SCHOOL!!!
'''


# Utils
BANNER = '''
 __   __  _______    __   __  __    _  ___   __   __  _______  ______    _______  ___   _______  __   __
|  | |  ||       |  |  | |  ||  |  | ||   | |  | |  ||       ||    _ |  |       ||   | |       ||  | |  |
|  |_|  ||  _____|  |  | |  ||   |_| ||   | |  |_|  ||    ___||   | ||  |  _____||   | |_     _||  |_|  |
|       || |_____   |  |_|  ||       ||   | |       ||   |___ |   |_||_ | |_____ |   |   |   |  |       |
|       ||_____  |  |       ||  _    ||   | |       ||    ___||    __  ||_____  ||   |   |   |  |_     _|
 |     |  _____| |  |       || | |   ||   |  |     | |   |___ |   |  | | _____| ||   |   |   |    |   |
  |___|  |_______|  |_______||_|  |__||___|   |___|  |_______||___|  |_||_______||___|   |___|    |___|
'''

STUDENT_NAME = "jayden_vs"

ALLOWED_CHARS = string.ascii_letters + string.digits

def randbytes(n): return bytes([random.randint(0,255) for i in range(n)])

def randomize_report(report):
    for _ in range(8):
        rand_bytes = randbytes(8)
        rand_loc = random.randrange(0, len(report) * 3 // 4)
        report = report[:rand_loc] + rand_bytes + report[rand_loc:]
    return report


# Classes
class ProofOfWorkSolver:
    def __init__(self, prefix_length=8):
        self.prefix_length = prefix_length

    def generate(self):
        prefix = ''.join(random.choices(ALLOWED_CHARS, k=self.prefix_length))
        self.nonce = ''.join(random.choices(ALLOWED_CHARS, k=16))
        return self.nonce, hashlib.sha256((prefix + self.nonce).encode('utf-8')).hexdigest()

    def verify(self, prefix, answer) -> bool:
        h = hashlib.sha256((prefix + self.nonce).encode('utf-8')).hexdigest()
        return h == answer


class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s

    def print_sig(self):
        print(f"Signature: ({self.r}, {self.s})")


class Ecdsa:
    def __init__(self, curve=ecdsa.curves.SECP256k1):
        self.curve = curve
        self.G = curve.generator
        self.n = self.G.order()
        self.d = random.randrange(1, self.n)
        self.Q = self.d * self.G
        self.recovery = None

    def sign(self, message: bytes, hashfunc=hashlib.sha256, resign=False) -> Signature:
        H = int(hashfunc(message).hexdigest(), 16)
        r, s = 0, 0
        while r == 0 or s == 0:
            k = random.randrange(1, self.n) if not resign else self.recovery
            self.recovery = k
            R = k * self.G
            r = R.x() % self.n
            s = ((H + r * self.d) * pow(k, -1, self.n)) % self.n
        return Signature(r=r, s=s)

    def verify(self, message: bytes, signature: Signature, hashfunc=hashlib.sha256) -> bool:
        H = int(hashfunc(message).hexdigest(), 16)
        r, s = signature.r, signature.s
        sinv = pow(s, -1, self.n)
        u1, u2 = (H * sinv) % self.n, (r * sinv) % self.n
        R = u1 * self.G + u2 * self.Q
        return R.x() % self.n == r


class Rsa:
    def __init__(self, bit_len=2048):
        self.p = getPrime(bit_len // 2)
        self.q = getPrime(bit_len // 2)
        self.N = self.p * self.q
        self.e = 3
        print(f"N = {self.N}")

    def encrypt(self, message: bytes):
        return b64encode(long_to_bytes(pow(bytes_to_long(message), self.e, self.N)))

    def decrypt(self, ciphertext: bytes):
        d = pow(self.e, -1, (self.p-1) * (self.q-1))
        return b64encode(long_to_bytes(pow(bytes_to_long(ciphertext), d, self.N)))


if __name__ == '__main__':
    print(BANNER)
    print("[+] System startup...")
    print(f"[!] Welcome to the super secure grading system, {STUDENT_NAME}.\n")
    powchal = ProofOfWorkSolver(prefix_length = 4)
    nonce, answer = powchal.generate()
    print(f'''Please solve the following challenge to show you are not a robot...\n
        sha256(???? + {nonce}) == {answer}\n''')
    prefix = input("Your answer: ")
    if not powchal.verify(prefix, answer):
        sys.exit('Goodbye, robot!')
    print("\n[+] Verification successful.\n")

    report = get_report_content()
    assert report is not None
    report = randomize_report(report)
    report_signed = STUDENT_NAME.encode('utf-8') + report

    print("[+] Verifying with Professor...")
    my_ecdsa = Ecdsa(ecdsa.curves.NIST384p)
    sig1 = my_ecdsa.sign(report_signed[:len(report_signed) // 2])
    sig1.print_sig()
    assert my_ecdsa.verify(report_signed[:len(report_signed) // 2], sig1)
    sig2 = my_ecdsa.sign(report_signed[len(report_signed) // 2:], hashlib.sha256, True)
    sig2.print_sig()
    assert my_ecdsa.verify(report_signed[len(report_signed) // 2:], sig2)
    print("\n[+] Verification successful.\n")

    print("[+] Distributing reports to tutors...")
    for i in range(1, 4):
        print(f"[-] Tutor {i}:")
        curr = Rsa(size(bytes_to_long(report)) + 64)
        print(f"Ciphertext = {curr.encrypt(report).decode('utf-8')}\n")
    print("[+] Distribution successful.\n")

    print("[+] I don't think you can forge it but hey, if you can really do so I will reward you the flag.")
    try:
        T = time()
        final_key = int(input("My secret key when communicating with professor: ").strip())
        if final_key == my_ecdsa.d:
            elapsed = 1000.0 * (time() - T)
            if elapsed >= 10000:
                print("[x] If you spend too much time the professor will know you are cheating!")
            else:
                print("[-] My system is broken :(")
                print(f"[-] Here is the flag: {FLAG}")
        else:
            print("[x] Seems I'm right, it is super secure!")
    except:
        sys.exit(f"[x] Bad hacking attempt!")
```

While the setup was quite nice, the vulnerabilities were quite the usual suspects. We are given 2 ECDSA signatures, with a common nonce, so the secret $k$ could be derived.

Next we are given 3 RSA encryptions, but due to the low exponent $e = 3$, it is just Hastad's attack as we are given the same number of encryptions as size of exponent.

Spent more time fixing careless mistakes, which were quite sneaky.

Firstly, when defining the class, I took the default value as the expected curve to work with

```python
class Ecdsa:
    def __init__(self, curve=ecdsa.curves.SECP256k1):
```

and did not notice that the actual curve initialized was different

```python
my_ecdsa = Ecdsa(ecdsa.curves.NIST384p)
```

Another mistake made, which highlights the importance of reading source code carefully was that the message from the RSA part did not have the student's name, and I mistakenly assumed the ECDSA and RSA messages were the same.

```python
report = randomize_report(report)
report_signed = STUDENT_NAME.encode('utf-8') + report
```

After that it was, just a matter of writing the proof of work solver and interacting with the server.

I'm not adding much explanation behind the reused nonces and Hastad's attack because these are well-documented outside.

### Solver

```python
import string
import sys
import ecdsa
import hashlib
import random
from tqdm import tqdm
from time import time
from base64 import b64encode,b64decode
import sympy
from sympy.ntheory.modular import crt
from itertools import permutations
from libnum import n2s,s2n
from pwn import *

STUDENT_NAME = "jayden_vs"

ALLOWED_CHARS = string.ascii_letters + string.digits

p = remote("104.197.118.147",10140)

class ProofOfWorkSolver:
    def __init__(self, prefix_length=8):
        self.prefix_length = prefix_length

    def generate(self):
        prefix = ''.join(random.choices(ALLOWED_CHARS, k=self.prefix_length))
        self.nonce = ''.join(random.choices(ALLOWED_CHARS, k=16))
        return self.nonce, hashlib.sha256((prefix + self.nonce).encode('utf-8')).hexdigest()

    def verify(self, prefix, answer) -> bool:
        h = hashlib.sha256((prefix + self.nonce).encode('utf-8')).hexdigest()
        return h == answer


perms = permutations(ALLOWED_CHARS, 4)
p.recvuntil(b'???? + ')
nonce = p.recvuntil(b')').decode('utf-8')[:-1]
p.recvuntil(b' == ')
target = p.recvline().strip().decode('utf-8')
print('nonce:', nonce)
print('target:', target)

for i in tqdm(perms, total=len(ALLOWED_CHARS)**4):
    prefix = ''.join(i)
    if hashlib.sha256((prefix + nonce).encode('utf-8')).hexdigest() == target:
        print("Found prefix:", prefix)
        p.sendline(prefix.encode())
        break

p.recvuntil(b'Signature:')
r1,s1 = eval(p.recvline().strip().decode('utf-8'))
p.recvuntil(b'Signature:')
r2,s2 = eval(p.recvline().strip().decode('utf-8'))

n = []
ct = []

for _ in range(3):
    p.recvuntil(b'N =')
    n1 = eval(p.recvline().strip().decode('utf-8'))
    n.append(n1)
    p.recvuntil(b'Ciphertext = ')
    ct1 = s2n(b64decode(p.recvline().strip()))
    ct.append(ct1)

print('N:', n)
print('ct:', ct)

M = crt(n,ct)[0]
m = int(sympy.root(M,3))
m = n2s(m)
STUDENT_NAME = b"jayden_vs"
m = STUDENT_NAME + m

h1 = int(hashlib.sha256(m[:len(m)//2]).hexdigest(), 16)
h2 = int(hashlib.sha256(m[len(m)//2:]).hexdigest(), 16)
g = ecdsa.curves.NIST384p.generator
q = g.order()
assert r1 == r2 # that means k is the same
k = ((h1 - h2) * pow(s1 - s2, -1, q)) % q

def verify(m,r,s) -> bool:
    H = int(hashlib.sha256(m).hexdigest(), 16)
    sinv = pow(s, -1, q)
    u1, u2 = (H * sinv) % q, (r * sinv) % self.q
    R = u1 * g + u2 * self.Q
    return R.x() % self.n == r

kinv = pow(k,-1,q)
rinv = pow(r1,-1, q)

print(m)
d = (((((s1 * k) % q) - h1) % q) * rinv) % q
print('d:',d)
p.sendline(str(d).encode())
p.interactive()
p.close()

#
```

### Flag

```
vsctf{Buff1ng_PuBL1c_k3y_CrYpT0(Gr4phy)_15_St1LL_1n53cur3}
```
