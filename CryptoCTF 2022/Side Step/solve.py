from telnetlib import Telnet

host, port = "01.cr.yp.toc.tf", 17331
LOCAL = False
# p = remote(host, port)
p = Telnet(host, str(port))
def sendBase(g):
    p.read_until(b'|\t[Q]uit\n')
    p.write(b'T' + b'\n')
    p.read_until(b'| please send your desired integer:')
    p.write(str(g).encode() + b'\n')
    line = p.read_until(b'| t, r = ', timeout=3)
    if b'Great' in line:
        print(line)
        p.interact()
    t,r = eval(p.read_until(b')').strip().decode('utf-8'))
    return t,r


import random
random.seed(0)
prime = 2 ** 1024 - 2 ** 234 - 2 ** 267 - 2 ** 291 - 2 ** 403 - 1
s = random.randint(2, (prime - 1) // 2)
print("Secret:", s)
Zp = Zmod(prime)

def testing(g, p):
    if not LOCAL:
        return sendBase(g)

    def pow_d(g, e, n):
        t, r = 0, 1
        for _ in bin(e)[2:]:
            if r == 4: t += 1
            r = pow(r, 2, n)
            if _ == '1': r = r * g % n
        return t, r

    def ts(m, p):
        m = m % p
        return pow(m, (p - 1) // 2, p) == 1
    
    if ts(g, p):
        t, r = pow_d(g, s, p)
        if r == 4:
            print("Solved")
            return True, True
        else:
            return t,r
    else:
        print("Failed quad residue")


def check(root):
    print("Root Bits check:", ZZ(root).nbits() , root)
    ans = Zp(2).nth_root(root)
    t,r = testing(ans, prime)

    # means solved
    if t == True and r == True:
        return True
    
    # increase bit size
    root <<= 1

    # if 4 does not appear, means the first bit needs to be set
    if t == 0:
        root |= 1

    return root

def refinedCheck(root):
    print("Root Bits Refined check:", ZZ(root).nbits())
    print("Root:", root)
    ans = Zp(4).nth_root(root)
    t,r = testing(ans, prime)

    if t == True and r == True:
        return True
    
    return False


def solve():
    s_high = 1
    for _ in range(1024):
        res = check(s_high)
        if res == True:
            print("Res:", res)
            print("Solved")
            return
        s_high = res

    for i in range(20):
        if i == 2:
            print(refinedCheck(s_high))

        s_high >>= 1
