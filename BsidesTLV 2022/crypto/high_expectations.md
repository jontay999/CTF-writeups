# High Expectations – Crypto (300)

### Description/Source

```python
import secrets
import flag

START_NUM_OF_PEOPLE = 60
PERFECT_SHOW = 2000
MAX_NUM_GAMES = 3000
RIGHT_GUESS = 60
WRONG_GUESS = 1
NUM_OF_SUITS = 4
NUM_OF_VALUES = 13

WELCOME_TEXT = """
You are a mentalist and now it's your show!
It's your chance to make the impossible possible!
Currently there are {} people in the show.
Your goal is to have {} people in it!

You can do it!
Magic is real!!
"""

SESSION_TEXT = """
There are {} people in the show
You pick a volunteer

You ask her to think on a card
"""

THINK_OF_A_SUIT_TEXT = """
You ask her to think on the suit of the card
You read her mind and choose:
    1) Spades
    2) Hearts
    3) Clubs
    4) Diamond
"""

THINK_OF_A_VALUE_TEXT = """
You ask her to think on the value of the card
Value between 1 and 13 when:
    1 is Ace
    2-10 are 2-10 :)
    11 is Jack
    12 is Queen
    13 is King
You read her mind and choose:
"""

RIGHT_GUESS_TEXT = """
Bravo! You did the impossible!
The applause you get attracts {} more people to the show!
"""

WRONG_GUESS_TEXT = """
Wrong answer :|
You probably read someone else's mind by mistake...

Someone left the show :(
"""

WIN_TEXT = "You Won! Here is your flag:"

LOSE_TEXT = """No one left in the show :(
Maybe you should practice more before...
"""

def red(text):
    return "\033[91m" + text + "\033[0m"

def green(text):
    return "\033[92m" + text + "\033[0m"

def purple(text):
    return "\033[95m" + text + "\033[0m"

# return a number between 1 and the given range
def rand_range(rng):
    return rng - (secrets.randbits(4) % rng)

def get_int(rng):
    while True:
        num_str = input(">> ")
        if not num_str.isdigit():
            print("Not a number, try again :/")
            continue
        num = int(num_str)
        if num <= 0 or num > rng:
            print(f"Not in range, choose between 1 and {rng}")
            continue
        break
    return num

def run_game():
    people = START_NUM_OF_PEOPLE

    print(WELCOME_TEXT.format(people, PERFECT_SHOW))
    for i in range(MAX_NUM_GAMES):
        if people <= 0:
            print(red(LOSE_TEXT))
            break
        if people >= PERFECT_SHOW:
            print(green(WIN_TEXT))
            print(flag.FLAG)
            break

        print(SESSION_TEXT.format(purple(str(people))))

        print(THINK_OF_A_SUIT_TEXT)
        rand_suit = rand_range(NUM_OF_SUITS)
        suit = get_int(NUM_OF_SUITS)

        print(THINK_OF_A_VALUE_TEXT)
        rand_value = rand_range(NUM_OF_VALUES)
        value = get_int(NUM_OF_VALUES)

        if suit == rand_suit and value == rand_value:
            print(green(RIGHT_GUESS_TEXT.format(RIGHT_GUESS)))
            people += RIGHT_GUESS
        else:
            print(red(WRONG_GUESS_TEXT))
            people -= WRONG_GUESS
    else:
        print("Sorry... the crowd is bored")

if __name__ == "__main__":
    run_game()

```

Basically guess suit + number correctly a sufficient amount of times to win. You have 3000 tries to try and get a score of 2000.

This can be solved by simply examining the distribution of random results mod 13

```python
import secrets

def rand_range(rng):
    return rng - (secrets.randbits(4) % rng)

d = {}
for i in range(100000):
    res = rand_range(13)
    c = d.get(res, 0)
    d[res] = c+1

print(d)

```

Which gives a heavy distribution weighted towards 11, 12, and 13

```
{4: 6186, 12: 12621, 3: 6269, 2: 6155, 8: 6287, 1: 6288, 13: 12509, 11: 12534, 10: 6225, 6: 6332, 5: 6299, 7: 6101, 9: 6194}
```

So we just guess any suit, and either 11,12, and 13, and get the flag

### Solver

```python
from pwn import *
host, port = "high-expectations.ctf.bsidestlv.com" ,8643
p = remote(host, port)
next_line = b'There are'

p.send(b'2\n12\n'*2800)
p.interactive()
```

### Flag

```
BSidesTLV2022{i_think_i7s_a_co0l_cHall3nge_bu7_1m_bi4s3d}
```
