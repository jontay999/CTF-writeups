# Securinets Quals/Finals 2022 – Category Challenges

## Category Challenge: escrime (Quals)

### Tags

- RSA

### Description/Source

```python
from Crypto.Util.number import getStrongPrime, getPrime, isPrime, bytes_to_long

FLAG = b"Securinets{REDACTED}"

def genPrime(prime):
    while True:
        a = getPrime(256)
        p = 2*prime*a + 1
        if isPrime(p):
            break
    while True:
        b = getPrime(256)
        q = 2*prime*b + 1
        if isPrime(q):
            break
    return p, q

prime = getStrongPrime(512)
p1, q1 = genPrime(prime)
p2, q2 = genPrime(prime)
assert p1 != p2 != q1 != q2

n1 = p1*q1
n2 = p2*q2
e = 65537

m1 = bytes_to_long(FLAG[:len(FLAG)//2])
m2 = bytes_to_long(FLAG[len(FLAG)//2:])

c1 = pow(m1, e, n1)
c2 = pow(m2, e, n2)

print(f"n1 = {n1}")
print(f"n2 = {n2}")
print(f"e = {e}")
print(f"c1 = {c1}")
print(f"c2 = {c2}")
```

### Solver

```python
from math import gcd
n1 = 5285941989924581490741575774796326221790301948671605967204654261159288826022690654909746856601734294076351436205238123432817696904524845143908229601315593896823359605609172777227518764838488130850768836467030938547486936412484230693105639039311878853055295612388722273133638524917106191321503530749409311343663516633298043891444321772817485480644504762143353706512690041092791539952154332856635651319630479019844011333570438615137628705917690349203588170944935681
n2 = 5512656145670579765357132887430527554149315293720001536465226567777071834432904027590899542293511871806792894769506962601330354553170015126601443256295513753986998761021594415121386822360537570074896704547101502955980189351257681515387379761554807684880212096397524725819607628411147885452294832392886405475830663300445429053365129797792206619514994944481130684176571005780217091773969415001961227566026934419626425934895777818074251010427154279687683891897394401
e = 65537
c1 = 3792561290017712418676552700903779226679678307521013229152018077539055935181708693237786486418411190513573593312739874489485768872374239333562352570689090751306553033406629945001093355613620844532659507519582518955178617942044813600181673015763469247380587771641089223066734168709065596269187564842646397647564064090886856491267151338586218098150720579275673440512159074650632829004798635425409766385176472514086448897744502264325566940224093583630788193949908215
c2 = 3222093169881176821995152873609430742364413196826316856495679228145853706169389758246323802005549827444022148276365869623395771621464376723299960525487777645386674088866891887984766934440527885549168365996216682223515034398685244541695223412679979637178695229351272286453267599205874775267533781360269542834699741976380260822746797186755978820611721151719635986648586937891954519919600047846994285652165076540057377973800029963140392459328016771048953153246246886

x = gcd(n1-1, n2-1)
x = 12397002878565866184412236037259205021945058505472864688501145731895119789392433217522880454989374040698621943547773164450323280239641723319936790061247301


# s = ((n1-1) // (2*x)) % (2*x)
# p = (n1-1-(2*x*s))//(4*x*x)
# d = isqrt(s*s-4*p)
# r1 = (s+d)/2
# r2 = (s-d)/2

# s = ((n2-1) // (2*x)) % (2*x)
# p = (n2-1-(2*x*s))//(4*x*x)
# d = isqrt(s*s-4*p)
# r1 = (s+d)/2
# r2 = (s-d)/2

# p1 = (2*x*r1+1)
# q1 = n1//p1
# assert n1 == p1*q1

p1 = 2379512101395798487589546994592639734445639927590880157026098535371028480043618027983541188345725229858979364921042070180141077634624641084702633176323705406144093690580461600766965055999817305445781548267413273853443168917163840647
q1 = 2221439423159016381393658394780105350792693322876648986474869866339368867807425200316438510866606396517767790464944841327114607702260463228404447182686345024798471732395372887380189018315999472169850229330112898479889219323240186423

p2 = 2786246048623897729286445871006374635910185826978600534769543337026629088633372429750033662275203813356938015540331438556664616128481677513687905625607187511510234318602542761785785938812765612836278539914737073257670226283799878903
q2 = 1978524527075859599595909374280095997561630162625870140007265579883247235661046637894365180263831726000013309951173493880479503234178680297555083087314698525287527688568633419919584923535838438694360230134814253141139226206119579367

from gmpy2 import invert
from libnum import n2s

d1 = int(invert(e,(p1-1)*(q1-1)))


d2 = int(invert(e,(p2-1)*(q2-1)))
print(n2s(pow(c1,d1,n1))+n2s(pow(c2,d2,n2)) )

#Securinets{G3n3r4t1ng_pr1m3s_1n_4_sp3c1f1c_f0rm_4lm0st_4lw4ys_3nds_b4dly}
```

## Crypto Challenge: yor_forger (Finals)

This was one of the most satisfying challenges to solve, mostly because its the first time I've successfully used LLL, and mostly because the whole question's math is way above my head but I somehow managed to cobble together something.

Main sources:

- [Forging shares](https://crypto.stackexchange.com/questions/54578/how-to-forge-a-shamir-secret-share)
- [LLL to solve CVP](https://colab.research.google.com/github/nguyenduyhieukma/CTF-Writeups/blob/master/Google%20CTF%20Quals/2019/reality/reality-solution.ipynb#scrollTo=pqq6W73gJw3T)

### Description

```
Trust in shares.
```

### Source

```python
#!/usr/bin/env sage
import json, hashlib
from secret import FLAG, SECRET

def hash(msg):
    return hashlib.sha256(msg.encode()).hexdigest()

class Shamir:
    def __init__(self, p, n, k):
        """
        p = prime number for modulo operations in Z_p
        n = number of shares
        k = minimum number of shares required to reconstruct the secret
        """
        self.p = p
        self.n = n
        self.k = k
        self.secret = int(hash(SECRET), 16)
        self.coeffs = [self.secret]
        self.shares = []
        self.poly = None

    def generate_shares(self):
        for _ in range(self.k-1):
            self.coeffs.append(randint(1, round(sqrt(self.p))))

        P = PolynomialRing(GF(self.p), "x")
        x = P.gen()
        self.poly = sum(c*x^i for i, c in enumerate(self.coeffs))

        for _ in range(self.n):
            xs = randint(1, 2^54)
            ys = self.poly(x=xs)
            self.shares.append((xs, ys))

    def get_share(self, i):
        return self.shares[i]

    def reconstruct_secret(self, shares):
        P = PolynomialRing(GF(self.p), 'x')
        x = P.gen()
        try:
            reconst_poly = P.lagrange_polynomial(shares)
            return reconst_poly(0)
        except:
            print("Invalid shares.")
            sys.exit()


if __name__ == "__main__":
    p = random_prime(2^512-1, False, 2^(512-1))
    sss = Shamir(p, 10, 5)
    sss.generate_shares()

    print("Here is 4 trusted shares :")
    shares = []
    for i in range(4):
        shares.append(sss.get_share(i))
    print({"p": p, "shares": shares})

    try:
        resp = json.loads(input("\nSend your share : "))
        xs, ys = int(resp['xs']), int(resp['ys'])
        assert 1 <= xs <= p-1 and 1 <= ys <= p-1
    except:
        print("You must send data using the expected format.")
        sys.exit()

    shares.append((xs, ys))
    if sss.reconstruct_secret(shares) == int(hash("gimme flag"), 16):
        print(f"Well done! Here is your flag {FLAG}")
    else:
        print("Not even close.")
```

We basically have 4 out of the necessary 5 shares in Shamir's Secret Sharing Scheme. The objective is to give the final share that will give the `int(hash("gimme flag"), 16)` when reconstructed from the original polynomial, essentially changing `SECRET` to that new target.

The `p` modulus given is 512 bits, but the coefficients are all less than 256 bits, which leads us to LLL, to help find a small basis of vectors (solutions) to a polynomial

```python
self.coeffs.append(randint(1, round(sqrt(self.p))))
```

My math is actually pretty bad, so I'll try to make sense of it but might have a bunch of wrong parts.

Using the 4 shares we are given, we can construct our initial matrix. Important note that LLL can only be done in ZZ or QQ, and not in Finite Fields (my silly ass just dumped `GF(P)` and thought it would work).

```
B = matrix(ZZ, [
    [1   , 1   , 1   , 1, 1, 0, 0, 0, 0],
    [x0  , x1  , x2  , x3, 0, 1, 0, 0, 0],
    [x0^2, x1^2, x2^2, x3^2, 0, 0, 1, 0, 0],
    [x0^3, x1^3, x2^3, x3^3, 0, 0, 0, 1, 0],
    [x0^4, x1^4, x2^4, x3^4, 0, 0, 0, 0, 1],
])
```

We need a way to say that the first 4 columns are a lot more important than the other 5 columns, so we need to scale up the first 4 columns. Using the above link of constructing LLL to solve CVP, we use a scaling factor of `2^256` up to the maximum value of the coefficients and `2^-512` for the other columns (other values may work as well), as long as you weight the first few columns.

(Initially I used a scale factor of `2^512` and got a solution but the coefficients were greater than the bounds given of square root `p`. Lesson learnt: scaling factor can be treated like the upper bounds of the possible solutions)

```
scale_factors = [2^256, 2^256, 2^256,2^256, 2^-512, 2^-512, 2^-512, 2^-512, 2^-512]
```

Now that we've scaled up our matrix, we need to use LLL to give the smallest basis for the RHS target of

```
t = vector(ZZ, [y0, y1, y2, y3, 2^255, 2^255, 2^255, 2^255, 2^255])
```

After plugging the matrix into the `solve_cvp2` function that I have taken off `nguyenduyhieukma`'s code. We derive the coefficients. Now we need to forge a share.

Following the link above about how to forge a share, the stackoverflow post assumed that there were 5 shares, and you had access to the `x` values of all of the 5 shares, but only your `y` value.

To fit it into the solution, we just needed to generate a new share using the coefficients we have and plug the formula in.

### Solver

Full Script

```python

def solve_cvp(B, t, verbose=False):
    """
    Approximately and efficiently solves the closest vector problem.

    Arguments:
        B: a matrix whose rows are the basis vectors.
        t: the target vector.
        verbose: if True, print out useful information while solving.

    Return:
        A vector in the lattice generated by `B` (approximately) closest to `t`.

    """
    #  perform vector projecting using the Gram-Schmidt process
    t_ = t - B.stack(t).gram_schmidt()[0].row(-1)
    if verbose:
        print( "Target vector projection:")
        print( numerical_approx(t_, digits=4))

    # apply the LLL algorithm
    B_ = B.LLL()
    if verbose:
        print( "\nLLL-reduced basis:")
        print( numerical_approx(B_, digits=4))

    # find the exact linear combination of vectors in `B_` that produces `t_`
    c = B_.solve_left(t_)

    # round each coefficient to its nearest integer
    c_ = vector(map(round, c))
    if verbose:
        print( "\nRound-off errors:")
        print( numerical_approx(vector(map(abs, c - c_)), digits=4))

    # output the result
    return c_ * B_


def solve_cvp2(B, t, scale_factors=None, verbose=False):
    """
    A wrapper of `solve_cvp` to perform coordinate scaling.

    Arguments:
        scale_factors: a list of scale factors. The 1st, 2nd, 3rd, ... factor
            will be used for the 1st, 2nd, 3rd, ... coordinate.

    """
    if not scale_factors:
        scale_factors = [1] * B.ncols()

    if verbose:
        print( "Scale factors:")
        print( numerical_approx(vector(scale_factors), digits=4), '\n')

    scale_matrix = diagonal_matrix(scale_factors)
    return solve_cvp(B*scale_matrix, t*scale_matrix, verbose) * scale_matrix^-1

data = {'p': 7056548466666807361047777121134211247322811831309071483431724560061912458066557536487288893034960254507165305004736759941042155412439162938595001536742657, 'shares': [(4190475185468033, 8365506247027717122158484727364478178249979938393474717944569038554294439015639968677760967139575968336263135528936929037105725345405282332), (333714650934662, 336465259764886683397586042207965620009159900357598280311574636266356652261258228016061876867111484194869489643621852914326100015233710), (11346479892543077, 449659451298127406046592584646725477187317673941324499529589373151360253189989339383915877404856747271429174741630015151657867886389776742620), (16450163368745154, 1986643754101079579888384101704652542193739394716318319520522234171852294763818226566828454356651641845262240827848843106317526090121790615150)]}
p = data['p']
shares = data['shares']

xs = [i[0] for i in shares]
ys = [i[1] for i in shares]
#all the shares
x0,x1,x2,x3 = xs
y0,y1,y2,y3 = ys


P = GF(p) #the prime modulus

#The matrix
B = matrix(ZZ, [
    [1   , 1   , 1   , 1, 1, 0, 0, 0, 0],
    [x0  , x1  , x2  , x3, 0, 1, 0, 0, 0],
    [x0^2, x1^2, x2^2, x3^2, 0, 0, 1, 0, 0],
    [x0^3, x1^3, x2^3, x3^3, 0, 0, 0, 1, 0],
    [x0^4, x1^4, x2^4, x3^4, 0, 0, 0, 0, 1],
])

def matrix_overview(BB):
  for ii in range(BB.dimensions()[0]):
    a = ('%02d ' % ii)
    for jj in range(BB.dimensions()[1]):
      if BB[ii,jj] == 0:
        a += ' '
      elif BB[ii,jj] == 1:
        a += '1'
      else:
        a += 'X'
      if BB.dimensions()[0] < 60:
        a += ' '
    print(a)

matrix_overview(B)

#give everything
t = vector(ZZ, [y0, y1, y2, y3, 2^255, 2^255, 2^255, 2^255, 2^255])

# scale_factors = [2^512, 2^512, 2^512,2^512, 2^-512, 2^-512, 2^-512, 2^-512, 2^-512]
scale_factors = [2^256, 2^256, 2^256,2^256, 2^-512, 2^-512, 2^-512, 2^-512, 2^-512]

closest_vector = solve_cvp2(B, t, scale_factors, verbose=True)

_y0, _y1, _y2,_y3, a0, a1, a2, a3, a4 = closest_vector

y_results = [_y0, _y1, _y2,_y3]
coeffs = [a0, a1, a2, a3, a4]

for i in range(len(coeffs)):
    assert coeffs[i] < sqrt(p)
    coeffs[i] = P(coeffs[i])

P = PolynomialRing(GF(p), "x")
x = P.gen()
poly = sum(c*x^i for i, c in enumerate(coeffs))

x_payload = randint(1, 2^54)
y_real = poly(x=x_payload)

import hashlib
def hash(msg):
    return hashlib.sha256(msg.encode()).hexdigest()
target = int(hash("gimme flag"), 16)

total_product = 1
total_product *= ((x0 - x_payload) / x0)
total_product *= ((x1 - x_payload) / x1)
total_product *= ((x2 - x_payload) / x2)
total_product *= ((x3 - x_payload) / x3)

y_payload = y_real + P((target-a0)) * P(total_product)

real_payload = (x_payload, y_payload)


payload_shares = shares + [real_payload]
reconst_poly = P.lagrange_polynomial(payload_shares)
assert reconst_poly(0) == target

final = {
    "xs": str(x_payload),
    "ys": str(y_payload)
}

print(final)
```

### Flag

```
Securinets{1nv4l1d_sh4r3_w4_s0nz41_suru!}
```
