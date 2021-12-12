# niteCTF – Prisoners

- **Category:** Misc
- **Points:** 500

## Challenge

We are given an instance to connect to. On connecting, we are given the prompt

```
A group of radicalists felt scientists like yourself were responsible for the corona virus outbreak.
Hence you and all your fellow scientists have been kidnapped and brought to this facility.
All of you have been injected with a specific strain of the virus which will kill you in an hour.
Here lie 100 doors inside which there is a vaccine numbered specifically for each one of you.
Now since the radicalists are not mean, they will give you a chance to live.
Each one of you can open upto 50 doors to search for your vaccine.
If you do not find your vaccine in those 50 tries, you die :)
If all 100 of you can find your vaccines, then all of you get to live.
```

Basically, you have 50 tries to open incorrect doors, and you need to get the correct doors of 100 people. If a wrong answer is given, the server responds with the doctor that the door corresponds to.

## Solution

1. The solution was just to keep trying every room sequentially and store all the answers in a dictionary.
2. There will be some instances where you fail but by leaving it on a loop, we eventually get the answer with probabilities

```
from pwn import *
while(True):
    p = remote(t3,1337)

    p.recvlines(14)
    d = {}
    count = 0
    try:
        while(count < 101):
            curr = p.recvline()
            doctor = curr.split(b'\n')[0][-2:]
            if(doctor in d):
                p.sendline(bytes(str(d[doctor]),'utf-8'))
                print("successfully guessed")
                print(p.recvlines(2))
            else:
                p.sendline(bytes(str(count), 'utf-8'))
                curr = p.recvline()
                actualDoctor = curr.split(b'\n')[0][-2:]
                if(actualDoctor == doctor):
                    print("success")
                    print(p.recvline())
                else:
                    d[actualDoctor] = count
                count += 1

        #to get the flag
        while(True):
            print(p.recvline())

    except Exception:
        p.close()
```

And after leaving it to run a while, we get the flag.

```
niteCTF{Pr0b4b1l1tY_c4n_5aVe_L1v3s}
```

## Thoughts

- A simple kind of brute force based on probabilities challenge
- Probably an implementation error but the flag given was in a different format than the competition.
