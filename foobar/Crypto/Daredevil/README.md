## Challenge Title: DareDevil

## Category: Crypto

TLDR

- We can send payload to server and it will sign it, or it can verify signature. If we pass the verify function , we get the flag.
- Try to make `pow(sign, e, n) == msg` where `msg = bytes_to_long(b'd4r3d3v!l')`
- We can't send the target payload immediately so just construct a `N` + payload which will decrypt to same thing cos everything is mod N

Solve Script to construct payload:

```
from libnum import n2s,s2n
from pwn import *

TOKEN = b'd4r3d3v!l'
hex_token = hex(s2n(TOKEN))[2:]

host = "chall.nitdgplug.org"
port = 30093
p = remote(host,port)
p.recvuntil(b">")
p.sendline(b'P')
p.recvline()
n_line = p.recvline()
n_line
n = int(n_line.strip().decode('utf-8').split(':')[1], 16)
p.recvline()
e_line = p.recvline()

e = int(e_line.strip().decode('utf-8').split(':')[1], 16)
print("n:", n)
print("e:", e)

to_sign = s2n(TOKEN) + n
to_sign = hex(to_sign)[2:].encode('utf-8')

print("To sign:", to_sign)

p.sendline(b'S')
p.recvuntil(b':')
p.sendline(to_sign)
p.recvline()
sig_line = p.recvline()

sig = sig_line.strip().decode('utf-8').split(':')[1]
p.sendline(b'V')
p.recvuntil(b':')

p.sendline(hex_token)
p.recvuntil(b':')
p.sendline(sig.encode('utf-8'))
p.interactive()

```

## Flag

```
GLUG{fl4g_15_53rv3d_xD_E9644V2GG0}
```
