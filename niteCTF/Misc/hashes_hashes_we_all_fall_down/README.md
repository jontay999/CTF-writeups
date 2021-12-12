# niteCTF – Hashes hashes we all fall down

- **Category:** Misc
- **Points:** 500

## Challenge

We are given a SHA-256 hash. The prepended salt was also given -- `salt` and the key was a word in the Bee Movie.

## Solution

1. Searching online got me an entire transcript of the movie.

Brute forcing every possible word as a key got the flag

```
from hashlib import sha256
with open('./beemovie.txt', 'r') as f:
    text = f.read()

target = "SHA-256 Hash"

words = [e for e in text.split() if e.isalnum()]

words = list(set(words))

for word in words:
    if(sha256(("salt"+word).encode()).hexdigest() == target):
        print(word)
        exit()
```

The key was Oinnabon.

```
nite{Oinnabon}
```

## Thoughts

- Just a simple brute force solution.
- Converted the list to set to remove duplicates but it probably wasn't very necessary
