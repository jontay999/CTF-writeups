#Given variables
#we are given n, from which p and q can be found from factordb
c = 19441066986971115501070184268860318480501957407683654861466353590162062492971
p = 172036442175296373253148927105725488217
q = 337117592532677714973555912658569668821
e = 17

#sage code
"""
P.<a>=PolynomialRing(Zmod(p))
f=a^e-c
mps=f.monic().roots()
#when f is monic, the output will have leading coefficient of either +- 1 depending on the degree
P.<a>=PolynomialRing(Zmod(q))
g=a^e-c
mqs=g.monic().roots()


for mpp in mps:
    x=mpp[0]
    for mqq in mqs:
        y=mqq[0]
        solution = int(CRT_list([int(x), int(y)], [p, q]))
        try:
            print(n2s(solution).decode('utf-8'))
        except:
            pass
"""
#CRT_list()
"""
takes in 2 lists:
remainder_list = [r1,r2,r3,..ri]
moduli list = [m1,m2,m3...mi]

returns a value (x) where

x % mi = ri

"""