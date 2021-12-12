# niteCTF – welcome to niteCTF

- **Category:** Web
- **Points:** 500

## Challenge

We are given the homepage of the website and tasked to simply "copy the flag"

## Solution

1. Looking at the components file at the `Footer.js`, I noticed a rather strange variable being loaded as the footer string.
2. On hovering over the regular footer text, the original text disappears.
3. Loading the strange variable which was assigned to the standard Javascript Obfuscation (e.g. ![]{][][]}....) into an online compiler yielded the flag.
4. Alternatively, I could have simply copied the hidden text on the website hahhah

```
nite{welcome_to_niteCTF2021}
```

## Thoughts

- This took way too long than it should have for me to complete hhahaa.
