## Starter ECC (Medium) - 43 solves

### Description/Source

```py
#!/usr/bin/env sage

from Crypto.Util.number import *
from secret import n, a, b, x, flag

y = bytes_to_long(flag.encode('utf-8'))

assert y < n
E = EllipticCurve(Zmod(n), [a, b])

try:
	G = E(x, y)
	print(f'x = {x}')
	print(f'a = {a}')
	print(f'b = {b}')
	print(f'n = {n}')
	print('Find the flag :P')
except:
	print('Ooops, ERROR :-(')
```

First we find out that the modulus is a product of small-ish prime powers

```py
assert n == 2**63 * 651132262883189171676209466993073**5 * 690712633549859897233**6
```

The objective is to essentially do `ECC.lift_x()`, to calculate the corresponding $y$ variable from the known $x$ variable which is difficult because of the composite modulo.

The ECC equation is $y^2 = x^3 + ax + b \ mod\ p$.

We need to find the answer for the equation in modulo prime powers of the 3 different constituents of the modulo and recombine using CRT.

$1.\  y^2 = x^3 + ax + b \ mod \ 2^{63} \\$
$2.\  y^2 = x^3 + ax + b \ mod \ 651132262883189171676209466993073^{5} \\$
$3.\  y^2 = x^3 + ax + b \ mod \ 690712633549859897233^{6}$

A typical method to do so is Hensel's Lemma. However in this case the `libnum` library has a lovely function called `sqrtmod_prime_power` which can save us all the trouble.

It basically gives a bunch of answers for $x^2 = y\  mod\  p^k$ using `sqrtmod_prime_power(y,p,k)`

We can calculate the $y$ directly with the original modulus and plug it in.

There are 4 possible solutions for $2^{63}$ and 2 solutions for each of the 2 other prime powers. This leaves us with 16 possible solutions, we can just iterate through all of them and test if its the flag.

### Solver

```python
from libnum import *
from itertools import product
x = 10715086071862673209484250490600018105614048117055336074437503883703510511249361224931983788156958581275946729175531468251871452856923140435984577574698574803934567774824230985421074605062371141877954182153046477020617917601884853827611232355455223966039590143622792803800879186033924150173912925208583
a = 31337
b = 66826418568487077181425396984743905464189470072466833884636947306507380342362386488703702812673327367379386970252278963682939080502468506452884260534949120967338532068983307061363686987539408216644249718950365322078643067666802845720939111758309026343239779555536517718292754561631504560989926785152983649035
n = 117224988229627436482659673624324558461989737163733991529810987781450160688540001366778824245275287757373389887319739241684244545745583212512813949172078079042775825145312900017512660931667853567060810331541927568102860039898116182248597291899498790518105909390331098630690977858767670061026931938152924839936

assert n == 2**63 * 651132262883189171676209466993073**5 * 690712633549859897233**6

factors = [
    (2,63),
    (651132262883189171676209466993073, 5),
    (690712633549859897233, 6)
]
y = (x**3 + a*x + b) % n

arr = []
for p,k in factors:
    arr.append(list(sqrtmod_prime_power(y, p, k))) #doesnt work in sage for some reason

arr = [[6872316419617283935, 6962741635664879777, 2351055617237491873, 2260630401189896031], [23938680681144110126864472369526527114232476444369009413993015648536857120441143070915552032112089272682314228841548237113124931414511899753656778603944647014377036, 93104488708926761818560246297264588770473566517002681750582133805540977796681339225523968578399954072257212403322866083943615139168215581722889802358371787185259557], [72352434828920450203010620988737832576343710008678726466724738614116886245209519198387416572447470167141418150681777608856472, 36236206072093682925062247481413370357729850833651633845213538784805223337120517698394707398791103046274787874369241081809097]]
primes = [2**63, 651132262883189171676209466993073**5, 690712633549859897233**6]
for i in product(*arr):
    try:
        i = list(i)
        pt = n2s(int(CRT_list(i, primes)))
        print(pt)
        if b'CCTF' in pt:
            print(pt)
            break
    except:
        pass
exit()

```

### Flag

```
 CCTF{8E4uTy_0f_L1f7iN9_cOm3_Up!!}  CCTF{8E4uTy_0f_L1f7iN9_cOm3_Up!!}  CCTF{8E4uTy_0f_L1f7iN9_cOm3_Up!!} _______________________
```

### References

- https://crypto.stackexchange.com/questions/72613/elliptic-curve-discrete-log-in-a-composite-ring
- https://www.quora.com/How-are-the-square-roots-of-x-modulo-a-composite-number-n-calculated-knowing-the-factorization-of-n-i-e-square-roots-x-mod-n-where-x-y-2-mod-n
- https://github.com/hellman/libnum/blob/master/README.md
- https://math.stackexchange.com/questions/1863037/discrete-logarithm-modulo-powers-of-a-small-prime
