# Crypto - Equation 1 (252)

## Challenge

```python
from Crypto.Util.number import bytes_to_long

FLAG = <REDACTED>

n = len(FLAG)
m1 = bytes_to_long(FLAG[:n//2])
m2 = bytes_to_long(FLAG[n//2:])

print(13 * m2 ** 2 + m1 * m2 + 5 * m1 ** 7)
print(7 * m2 ** 3 + m1 ** 5)

# 13 * m2 ** 2 + m1 * m2 + 5 * m1 ** 7 == 6561821624691895712873377320063570390939946639950635657527777521426768466359662578427758969698096016398495828220393137128357364447572051249538433588995498109880402036738005670285022506692856341252251274655224436746803335217986355992318039808507702082316654369455481303417210113572142828110728548334885189082445291316883426955606971188107523623884530298462454231862166009036435034774889739219596825015869438262395817426235839741851623674273735589636463917543863676226839118150365571855933
# 7 * m2 ** 3 + m1 ** 5 == 168725889275386139859700168943249101327257707329805276301218500736697949839905039567802183739628415354469703740912207864678244970740311284556651190183619972501596417428866492657881943832362353527907371181900970981198570814739390259973631366272137756472209930619950549930165174231791691947733834860756308354192163106517240627845889335379340460495043
```

We note that `m1` and `m2` are around the same size. Since the result of the first equation is rather large and is largely dominated by the term `m1^7`, we can make an approximation of `m1` by ignoring the rest of the terms of lower degree. This gives us `m1` immediately and `m2` can be deduced.

## Solution

```python
from libnum import n2s
import gmpy2
# 13 * m2 ** 2 + m1 * m2 + 5 * m1 ** 7 == 6561821624691895712873377320063570390939946639950635657527777521426768466359662578427758969698096016398495828220393137128357364447572051249538433588995498109880402036738005670285022506692856341252251274655224436746803335217986355992318039808507702082316654369455481303417210113572142828110728548334885189082445291316883426955606971188107523623884530298462454231862166009036435034774889739219596825015869438262395817426235839741851623674273735589636463917543863676226839118150365571855933
# 7 * m2 ** 3 + m1 ** 5 == 168725889275386139859700168943249101327257707329805276301218500736697949839905039567802183739628415354469703740912207864678244970740311284556651190183619972501596417428866492657881943832362353527907371181900970981198570814739390259973631366272137756472209930619950549930165174231791691947733834860756308354192163106517240627845889335379340460495043
gmpy2.get_context().precision=3000
c1 = 6561821624691895712873377320063570390939946639950635657527777521426768466359662578427758969698096016398495828220393137128357364447572051249538433588995498109880402036738005670285022506692856341252251274655224436746803335217986355992318039808507702082316654369455481303417210113572142828110728548334885189082445291316883426955606971188107523623884530298462454231862166009036435034774889739219596825015869438262395817426235839741851623674273735589636463917543863676226839118150365571855933
c2 = 168725889275386139859700168943249101327257707329805276301218500736697949839905039567802183739628415354469703740912207864678244970740311284556651190183619972501596417428866492657881943832362353527907371181900970981198570814739390259973631366272137756472209930619950549930165174231791691947733834860756308354192163106517240627845889335379340460495043

m1 = int(gmpy2.root(c1 // 5, 7))
m2 = int(gmpy2.root((c2 - m1**5) // 7, 3))
print(n2s(m1) + n2s(m2))
```

## Flag

```
grey{solving_equation_aint_that_hard_rite_gum0pX6XzA5PJuro}
```