from pwn import *
from libnum import *
from sympy import *
# nc 05.cr.yp.toc.tf 37377



B = 2 << 127
primes = []
for i in range(10):
    B = nextprime(B)
    print(B)
    primes.append(B)

print(2**64+1)

def solve():
    host, port = "05.cr.yp.toc.tf",37377
    p = remote(host, port)
    p.interactive()

