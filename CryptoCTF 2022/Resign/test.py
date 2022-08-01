
from Crypto.Util.number import *
import random

def getP(primes, bit):
	filtered = [i for i in primes if int(i).bit_length() == bit]
	return random.choice(filtered)

def gen_primes(nbit, imbalance, primes):
	p = 2
	while True:
		while int(p).bit_length() < nbit - 2 * imbalance:
			# factor = getPrime(imbalance)
			factor = getP(primes,imbalance)
			p *= factor
		rbit = (nbit - int(p).bit_length()) // 2
		if rbit > 6 : break

	print("out of here")

	while True:
		r, s = [getP(primes,rbit) for _ in '01']
		_p = p * r * s
		if int(_p).bit_length() < nbit: rbit += 1
		if int(_p).bit_length() > nbit: rbit -= 1
		if isPrime(_p + 1):
			p = _p + 1
			break

	return p


ps = [2] + list(primes(2**10))
pps = [[ps[i] for i in range(0,len(ps),2)], [ps[i] for i in range(1,len(ps),2)]]
p,q = [gen_primes(1024,10, pps[i]) for i in range(2)]