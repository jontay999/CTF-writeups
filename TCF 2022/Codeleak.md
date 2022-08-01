## Misc Challenge: Code Leak

Note: upsolved, but did a writeup because I found it interesting

### Description/Source

We are given a Dockerfile as well as the source for `main.py`

```Dockerfile
FROM python:latest

RUN /usr/sbin/useradd --no-create-home -u 1000 ctf

WORKDIR /home/ctf

COPY main.py .
COPY controller.py .

RUN apt-get update
RUN apt-get install -y socat

RUN chown -R root:root /home/ctf

USER ctf

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 main.py"
```

```py
# main.py
import ast

from controller import Controller

user = input("Enter your name: ")
controller = Controller(user)

def safe_eval(code):
  tree = compile(code, "<string>", 'exec', flags=ast.PyCF_ONLY_AST)
  for x in ast.walk(tree):
    if type(x) not in (ast.Module, ast.Expr, ast.Attribute, ast.Name, ast.Load):
      return "Invalid operation"

  return eval(code)

def secret_debugger():
  while True:
    try:
      code = input("DEBUG>>> ")
      print(safe_eval(code))
    except Exception as x:
      print(x)
      break

def menu():
  while True:
    print("""What would you like to do?
    1. Check balance
    2. Work
    3. Buy hint ($30)
    4. Buy flag ($1337)
    5. Exit
    """)

    choice = input(">>> ")
    message = ""

    if choice == "1":
      message = controller.check_balance()
    elif choice == "2":
      message = controller.work()
    elif choice == "3":
      message = controller.buy_hint()
    elif choice == "4":
      message = controller.buy_flag()
    elif choice == "5":
      print("Bye!")
      exit()

    if choice == "42":
      secret_debugger()

    print(message)

menu()
```

From this line in the Dockerfile, we can tell that its using python3.10

```
FROM python:latest
```

So we are to try and figure out the code in the class `Controller` and how the `buy_flag` function works.

We are allowed to enter a debugger that only allows us to read existing variables, but no assigning values or initializing new variables or function calls.

```py
if type(x) not in (ast.Module, ast.Expr, ast.Attribute, ast.Name, ast.Load):
    return "Invalid operation"
```

If you try interacting with the menu you realise that you can only work 6 times and you earn less than 10 bucks each time so there's no way to buy the flag which costs 1337.

Exploring the values in the `controller` class, we can see that there is an encrypted flag.

```python
DEBUG>>> controller
<controller.Controller object at 0x7ffbfce34100>
DEBUG>>> controller.__dict__
{'name': 'test', 'money': 0, 'works': 0, 'encrypted_flag': 'Q(\x02\x90Ø´Õ\x87kª;NÌü\n\x83¢ÀI©ögUä¾Z4\x1eþÜIv\x03æx\x90{~'}
```

We can explore the methods available in the class

```py
DEBUG>>> Controller.__dict__
{'__module__': 'controller', '__init__': <function Controller.__init__ at 0x7ffbfcee76d0>, 'buy_flag': <function Controller.buy_flag at 0x7ffbfcee7760>, 'check_balance': <function Controller.check_balance at 0x7ffbfcee77f0>, 'work': <function Controller.work at 0x7ffbfcee7880>, 'buy_hint': <function Controller.buy_hint at 0x7ffbfcee7910>, '__dict__': <attribute '__dict__' of 'Controller' objects>, '__weakref__': <attribute '__weakref__' of 'Controller' objects>, '__doc__': None}
```

So there is no decrypt function, which means that it is likely that the method to decrypt the flag is within `buy_flag` itself.

We can try to explore the `__code__` object, referencing off the variables available here

> The \_\_code\_\_ object contains the raw bytecode ( co_code ) of the function as well as other information such as constants and variable names.

```py
DEBUG>>> Controller.buy_flag.__code__
<code object buy_flag at 0x7ffbfce9f9f0, file "/home/ctf/controller.py", line 11>
```

The page [here](https://www.codeguage.com/courses/python/functions-code-objects) explains quite a bit of the variables that you can access

```
co_nlocals — is the number of local variables used by the function (including arguments).
co_argcount — is the total number of positional arguments (including positional-only arguments and arguments with default values).
co_varnames — is a tuple containing the names of the local variables (starting with the argument names).
co_names — is a tuple containing the names used by the bytecode.
co_cellvars — is a tuple containing the names of local variables that are referenced by nested functions.
co_freevars — is a tuple containing the names of free variables; co_code is a string representing the sequence of bytecode instructions.
co_posonlyargcount — is the number of positional-only arguments (including arguments with default values).
co_kwonlyargcount — is the number of keyword-only arguments (including arguments with default values).
co_firstlineno — is the first line number of the function.
co_lnotab — is a string encoding the mapping from bytecode offsets to line numbers (for details see the source code of the interpreter).
co_stacksize — is the required stack size.
co_code — is a string representing the sequence of bytecode instructions.
co_consts — is a tuple containing the literals used by the bytecode.
co_flags — is an integer encoding a number of flags for the interpreter.
```

In particular, I want to focus on the `co_consts`, `co_names` and `co_varnames`

```py
DEBUG>>> Controller.buy_flag.__code__
<code object buy_flag at 0x7ffbfce9f9f0, file "/home/ctf/controller.py", line 11>
DEBUG>>> Controller.buy_flag.__code__.co_consts
(None, 1337, ' does not have enough money', 133773211629381620483, 0, 256, '')
DEBUG>>> Controller.buy_flag.__code__.co_varnames
('self', 'flag', 'x', 'i', 'flag_ascii')
DEBUG>>> Controller.buy_flag.__code__.co_names
('money', 'name', 'encrypted_flag', 'append', 'ord', 'random', 'seed', 'range', 'len', 'randint', 'chr', 'join')
```

From this we can kind of intuit what is going on.

The first `1337` in the `co_consts` is probably used in the first check in the `Buy Flag ($1337)` based on the menu when you try to use that option

```
What would you like to do?
    1. Check balance
    2. Work
    3. Buy hint ($30)
    4. Buy flag ($1337)
    5. Exit
```

We know that the `random.seed` function is probably called based on `co_names` and so we can guess that the long number is probably the seed

`randint(0,256)` is then called and probably passed into `chr` and probably used as a character by character `xor` encryption (guessing this because of the lack of any other function calls or constants)

From this, we can guess that the encryption/decryption is something like

```py
random.seed(133773211629381620483)
ct = ''
for i in flag:
    ct += chr(i ^ random.randint(0,256))
```

Since we have the encrypted version of the flag we can try to test our assumptions.

### Solver

```python
import random
ct = "Q(\x02\x90Ø´Õ\x87kª;NÌü\n\x83¢ÀI©ögUä¾Z4\x1eþÜIv\x03æx\x90{~"

random.seed(133773211629381620483)
flag = ''
for i in ct:
    flag += chr(ord(i) ^ random.randint(0,256))

print(flag)

```

### Flag

```
TFCCTF{r3ad1ng_1s_3n0ugh_8na612nz020a}
```

### References

- https://chriswarrick.com/blog/2017/08/03/gynvaels-mission-11-en-python-bytecode-reverse-engineering/
- https://github.com/Hiumee/CTF/tree/main/TFCCTF/2022
- https://gist.github.com/tzlils/5779d03919d6873debd1e20baba6c84b
