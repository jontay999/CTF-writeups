# niteCTF – Mailman 1

- **Category:** OSINT
- **Points:** 500

## Challenge

We are given the prompt
`Our CTO takes Git commits quite seriously. Someone in our discord channel got an email from him. Now the person wants a similar email signature like the CTO of our company, so he decided to make an email signature of his own and commit it securely. Find the account's mail and wrap it with nite{} for the flag`

I didn't attempt it before the hint was out, so when I tried it, there was a free hint that gave the username of the discord user

## Solution

1. Checked the user's profile and found a link to his github repo
2. He only had 1 repository with a `README.md` and a `confidential.zip`
3. The zip file was encrypted, but the hintswas that the git commits were involved in the encryption. After trying a few combinations, the git commit hash right before the zip file was uploaded was the password
4. We get an `email.png` which had a bunch of words. Running the image through `stegsolve.jar` again led tot he email being shown.

```
nite{reply.nite@gmail.com}
```

## Thoughts

- My first OSINT challenge solved hahhaha.
- The stuff about the CTO was a red herring.
