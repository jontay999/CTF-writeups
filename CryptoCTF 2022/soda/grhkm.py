# from @grhkm

from pwn import *
from Crypto.Util.number import bytes_to_long

r = remote('01.cr.yp.toc.tf', 37711)
def query(p):
    assert is_prime(p) and int(p).bit_length() <= 128
    r.sendline(b't')
    r.sendline(str(p).encode())
    r.recvuntil(b'soda(g, p, q, m) = ')
    return ZZ(r.recvline().decode().strip())

# hard-coded since it's the same every connection
# doesn't matter if it changes every connection
n = 99079213864225638211164004707660376360561061293868813414340853792016960003532290684350987975057143145176307506763351191420928302748101383361521210974297633813257059844605439910514985971362362677843666944971712543939026392257685421348762705964915220795881554670574231326045740084163983602187913327355090728057
g = 31337

# our goal is to recover g^(1 / _e) below
CRY = "Long Live Crypto :))"
m = bytes_to_long(CRY.encode('utf-8'))
_e = 2 * ZZ(ZZ(pow(g, m^2, n)) % 2**152) + 1

# factor into prime factors - you see that _e = pqrs i.e. product of 4 primes
ft = list([p for p, _ in factor(_e)])
assert product(ft) == _e

# idea is something like this:
# suppose g3 = g^(1 / 3) and g5 = g^(1 / 5)
# notice that 1 / 15 = 2 / 3 - 1 / 5
# then, g^(1 / 15) = g3^2 * g5^(-1)
# and we can circumpass the restriction of p.bit_length() <= 128 on the query

# now, we want to construct 1 / (pqrs) from linear combination of 1 / p, 1 / q, 1 / r, 1 / s
# equivalent to constructing 1 from linear combination of qrs, prs, pqs, pqr
# solution guaranteed by bezout's lemma
M = Matrix(ZZ, [[_e // k for k in ft]])
coef = M.smith_form()[2][:, 0]
assert (M * coef)[0, 0] == 1

# now we query g^(1 / p_i), and combine them using the coefficients above mod n
res = [query(p) for p in ft]
ans = product(pow(res[i], coef[i, 0], n) for i in range(4)) % n

# verify on server
r.sendline(b'v')
r.recvuntil(b'to verify: \n')
r.sendline(str(ans).encode())
r.recvuntil(b'flag: ')
print(r.recvline().decode())