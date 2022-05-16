import hashlib

txs = [
#from 0x488dad0ce94f34e33069b8ae5e16826b63f0f575
'0x6705735d1d4c526cd5db6c5810de6b11ba196fb93715a67ae855d037bfeaeaec', #borrow
'0x657b24138cea98eca019de351d60c69210334926c46d9bfb7a59f5c0db5d16f4', #borrow
'0xdb3f9da9cc6600ba9c2ca0685cd5c29818dae632fb3be65d530ef404b3ade202', #borrow
'0x6b52684eda64076701e647911f55019fb18b30d980554dd2df5ee0e777506c3a', #borrow
'0x95bc3879debc5ffbe9932d5a60dd53146374e7dd553fef5f00152371bbb75f38', #borrow
'0xf8cb1d747b53bbd4b4346eb8522fa3df36025dafedeb5b19bf54a9fff946ae8a', #borrow
'0xef40506ae849c17dfbb75f97331860750217602f9c0a9c7718e50d04f0e233b8', #create position
'0xcc8ff167cc6a1014f5c4b7445f26b17f68cc95bcc0c578c5330278dda8229d0b', #create position

#from 0x941c73fbb405a9024c08a52cbeeaf80d02d2b1a1
'0x99a5722bb73a73c6b47967f9b457e888d6503b0f9e1bf23fbf36de56ebad1522', #borrow
'0x8beb80929a026d68fe9e80d0e46dadf43f9b8c68dc1db7e53b996e9654a3c71c', #borrow
'0x13240bc2ce9333db092704b057083d23fa4e365b1b049ea839eb9955591ffd4d', #borrow
'0x3a109f0754113742eaae4bad747261aa7d9a1a9e2fb4d12704631b333b790006', #borrow
'0x8b0b5a0d65a1272d811f1db90cf7a24e43c64cf0d4767a78accf0dd9afce954c', #borrow
'0xdd588f3c2a9f25aa57d27e3257fe93882cf211470bd92e56b5271f95ab3c955f', #borrow
'0x6287be53eb87e475cfdabfe85c7db800c5262a469a4c270e55b8ddf481b6dae3', #borrow
'0x6ce3f133f0d925b125b6d8861b582cfd3b9abc8df4ce6ecd9607751b5fa6e796', #borrow
'0xcfb692d772f8acb90bc14a5da06f72c8ed9d871bbe76787ac0fa8a40e1ef11aa', #borrow
'0x0635eeabe77d53672c227c0938f73f43c8f43b984e2c02d4e4a7b4e4d9740a09', #borrow
'0xc20e2ac5792a3350febd9a7e62527faccf4e07de2c1454572380e6f629ecca18', #create position
'0xb1f54b9969ba60075775a3168d2ad16482e672cbf386ba4f9d6f433fe9d86fbe', #create position

#from 0xb09c603ea024b4435d74db07d1f728a80e6e36ae
'0xea24903d0a72b56457b88bdfd842f4065b0371b9c118dae08aca8dadb43c81b4', #borrow
'0xf7a6068687cfd85a24c8fd169c3c95133ff7a957c843171733902925990b4b74', #create position


]

assert len(txs) == 22
salt = b'hint: find abnormal transactions'
m = hashlib.sha256()
for tx_hash in sorted(txs):
    assert len(tx_hash) == 66 and tx_hash[:2] == '0x'
    m.update(salt + tx_hash.encode() + m.digest())
print(m.hexdigest())
assert m.hexdigest()[:16] == 'bf22a2d63563554c'
print('flag{' + m.hexdigest() + '}')

