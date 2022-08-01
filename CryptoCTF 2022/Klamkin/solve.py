# nc 04.cr.yp.toc.tf 13777
from pwn import *
from libnum import *
"""
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|  Hello, now we are finding the integer solution of two divisibility  |
|  relation. In each stage send the requested solution. Have fun :)    |
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| We know (ax + by) % q = 0 for any (a, b) such that (ar + bs) % q = 0
| and (q, r, s) are given!
| Options: 
|       [G]et the parameters 
|       [S]end solution 
|       [Q]uit
G
| q = 224490285770321682606461173502326265411
| r = 36832841709076515032147614253207665787
| s = 30032559171722262237820217201429962140
"""

q = 325729570283337093050350174899088694381
r = 312556704284690216591398346568857384535
s = 56148108437440312246654313011839929156

x = 1<<26 +1
print(y.bit_length())
# assert y.bit_length() == 12

a = 1
b = (-r * pow(s,-1,q)) % q 
assert (a*r + b*s) % q == 0

y = ((-a*x) * pow(b,-1,q)) % q

assert (a*x + b*y) % q == 0
print(x,y)
