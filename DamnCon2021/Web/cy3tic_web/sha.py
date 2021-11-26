import hashlib

target = "86e6b53978acaba4401bd838b3aff9c74565ce84"
def sha(n):
    original = n
    for i in range(100):
        n = str.encode(n)
        n = hashlib.sha1(n).hexdigest()
        if(n == target):
            print("got it")
            print(original)

for i in range(13000000,13000051):
    test = str(i) + "DSPH"
    sha(test)
