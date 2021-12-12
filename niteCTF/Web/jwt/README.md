# niteCTF – jwt

- **Category:** Web
- **Points:** 500

## Challenge

We are given a website where we can enter a username and generate a jwt token. Once our jwt token is set as a cookie we can click verify to see if the admin parameter is true

## Solution

1. Decoding the token in [jwt.io](https://jwt.io) showed that there were 3 parameters. Namely: username, admin_cap, and kid.
2. Admin-cap probably stands for admin capabilities and the main exploit was how to modify this parameter and have a valid signature
3. The `kid` paramter was quite interesting as it was a path `http://localhost:3000/secret.txt`. This likely meant that the server is looking at the path encoded in this parameter to find the secret used to sign the key.
4. This could be tested out by modifying the parameter to a random constant like `test` which would give a 500 Internal Server Error
5. Using beeceptor as my end point, I set up a rule to return `test` when the path is queried.
6. After that I created a new token with admin_cap set to true and the kid parameter as the relevant beeceptor endpoint, and signed it using HS256.
7. After setting the cookie we get the flag

```
nite{R3diR3ct10n_c4n_b3_4_vuLn_t0O}
```

## Thoughts

- Very similar to the Naughty or Nice writeup I did for CyberSanta as well
