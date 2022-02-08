from libnum import n2s
from gmpy import invert
from random import randint

n = 57996511214023134147551927572747727074259762800050285360155793732008227782157
e = 17
c = 19441066986971115501070184268860318480501957407683654861466353590162062492971

p = 172036442175296373253148927105725488217
q = 337117592532677714973555912658569668821

assert p*q == n
assert (p-1)%e**2 == 0
assert (q-1)%e**2 == 0

phi = (p-1) *(q-1)//(e**4)

def getGenerator():
    phi = (p-1) *(q-1)//(e**4)
    g2 = pow(randint(1,n-1),phi,n)
    g3 = pow(randint(1,n-1),phi,n)
    assert pow(g2,e**2,n) == 1 #means that the generator is cyclic and has e^2 elements
    assert pow(g3,e**2,n) == 1 
    return g2,g3

def decode(g1,g2):
    d = int(invert(e,phi))
    pt_divisor = pow(c,d, n)

    for i in range(e**2):
        for j in range(e**2):
            x,y = pow(g1,i,n), pow(g2,j,n)
            flag_num = (pt_divisor*x*y) %n
            flag = n2s(flag_num)
            if(b'dice' in flag):
                print(flag, i,j)


gen1,gen2 = getGenerator()
decode(gen1,gen2)