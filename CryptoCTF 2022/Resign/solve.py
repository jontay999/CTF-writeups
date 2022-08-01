from pwn import *
from hashlib import sha1
from Crypto.Util.number import *
from sympy import *
from math import gcd

# nc 03.cr.yp.toc.tf 11137
host, port = "03.cr.yp.toc.tf" ,11137

MSG = b'::. Can you forge any signature? .::'
h = bytes_to_long(sha1(MSG).digest())

primes = list(primerange(3,1024))
p1s = [i for i in range(0,len(primes), 2)]
p2s = [i for i in range(1,len(primes), 2)]

def getNicePrimes():
    target_bitlength = 1024
    while True:
        p1 = 2
        while p1.bit_length() < target_bitlength:
            p1_next = random.choice(p1s)
            p1 *= p1_next
        
        while not isPrime(p1 + 1):
            p1_next = random.choice(p1s)
            p1 *= p1_next
            if p1.bit_length() > target_bitlength *2:
                break
        
    while True:
        p2 = 2
        while p2.bit_length() < target_bitlength:
            p2_next = random.choice(p2s)
            p2 *= p2_next
        
        while not isPrime(p2 + 1):
            p2_next = random.choice(p2s)
            p2 *= p2_next
        
        print("Bit length")
        return p1+1,p2+1






def gen_primes(nbit, imbalance):
	p = 2
	FACTORS = [p]
	while p.bit_length() < nbit - 2 * imbalance:
		factor = getPrime(imbalance)
		FACTORS.append(factor)
		p *= factor
	rbit = (nbit - p.bit_length()) // 2
	print('rbit:', rbit)

	while True:
		r, s = [getPrime(rbit) for _ in '01']
		_p = p * r * s
		if _p.bit_length() < nbit: rbit += 1
		if _p.bit_length() > nbit: rbit -= 1
		if isPrime(_p + 1):
			FACTORS.extend((r, s))
			p = _p + 1
			break

	FACTORS.sort()
	return (p, FACTORS)

p = remote(host, port)
p.sendlineafter(b'[Q]uit\n', b'P')
p.recvuntil(b'| SIGN = ')
sig = eval(p.recvline().strip().decode('utf-8'))

from sympy.ntheory import discrete_log
from sympy.ntheory.modular import crt
"""
x^e % n = h
x^e % p = h1 
x^e % q = h2


crt([mods], [residues])
discrete_log(mod, residue, base b)
discrete_log(41, 15, 7)
3 ^ 15 mod 41 = 7
It's considerably faster when your prime modulus has the property where p - 1 factors into a lot of small primes.
"""

while True:
    try:
        smoothness = 10
        p1,q1 = gen_primes(1024,smoothness), gen_primes(1024,smoothness)
        prime1, f1 = p1
        prime2, f2 = q1

        print("GCD:", gcd(prime1-1,prime2-1))


        d1 = int(discrete_log(prime1, sig % prime1, h % prime1))
        d2 = int(discrete_log(prime2, sig % prime2, h % prime2))

        magic_exponent = crt([prime1-1, prime2-1], [d1,d2])
        print()
        
        assert pow(h,d1, prime1) == (sig % prime1), "First Check"
        assert pow(h,d2, prime2) == (sig % prime2), "Second Check"
        # breakpoint()
        assert pow(h,magic_exponent[0], prime1*prime2) == sig, "Third Check"
        break
    except Exception as e:
        print("Error:", e)



print(f"Prime1: {prime1}, Prime2: {prime2}")



# exp = 1<<20
# while True:
#     try:
#         exp = nextprime(exp)
#         print("Trying prime:", exp)
#         d = pow(exp,-1,(p1[0]-1)*(q1[0]-1))
#         ct = pow(sig,exp, p1[0]*q1[0])
#         assert pow(ct,d,p1[0]*q1[0]) == sig
#         break
#     except Exception as e:
#         print(e)
#         continue

p.sendlineafter(b'[Q]uit\n', b'G')
p.sendline(f"{magic_exponent}, {prime1}, {prime2}")
p.interactive()


"""
g1 = Mod(h,p-1)
g2 = Mod(h,q-1)
c1 = discrete_log(sig,g1)
c2 = discrete_log(sig,g2)
CRT_list([c1,c2], [p-1, [q-1]])


q = 35212028070377057395757731961231931873381639047852453120379468949260520974623916426649929318615836136839011747239804867023117217952903149258918232596670846973065512585901954632858765023205631906210725359108153915300916294525560828569769210021313583072053453044054909830082588240703150051850274465294317811579
p = 76887153743509350755914180143237985044488814286878412890826798747237412531004092587835592467381233467058776833563207737233308865399730662948469336810119400692194485048719335268887372985244300001090603322697359086057440395681663685141468685170000921141897522871379462438725854141315679251603869513726417750579

p,q = 2 * 173^47 * 227^86+1, 2^524 * 541^55+1

s = 7954893866733656500294145160561912016717505637974860735264138433722641073191161788069157623755082318589340515651341180905616657431087951174625125471316466451150975792304282371512928083831765168500763135746444130450795095901287172691221522427405502545389016081232386433391933118298089277216541127231907902917422983792095832023252149801775211789740904222127693032188586059118883462713975031786063015276195086061533654156841346383707800341042929519375510873266019682346825010898437618718924984111640538814865894297841715281730692761553097150846854749210365162026263563687430356284276150599363952062239368372287189427047
h = 859134015240994359820678247621894875833976723365
def get_e(s):
sp = GF(p)(s)
sq = GF(q)(s)
dp = sp.log(h)
dq = sq.log(h)
    d = crt([dp, dq], [p-1, q-1])
    return pow(int(d), -1, lcm(p-1, q-1)).lift()
"""