# KnightCTF 2022 – Stego Challenges

## Challenge 1: FileD (25 points)

There were a bunch of files given but most of them were unimportant. There was a `filed.kra` that was the largest file at around 17.2Mb which was interesting

Searching online showed that `krita`, a software for image editing (similar to Gimp) was used to open `.kra` files

### Solution

1. Download krita
2. Open file and remove layers until flag is found

![flag](./images/1.png)

### Flag

```
KCTF{W00_n1ce_you_got_me}
```

## Challenge 2: Follow the White Rabbit (25 points)

We are given a jpeg of a white rabbit

### Solution

1. Open the image in `stegsolve` and iterate through filters until morse code is found
2. Decode morse code for flag

![flag](./images/2.png)

### Flag

```
KCTF{L0OKB4Y0UL34P}
```

## Challenge 3: QR Code from the Future (100 points)

A gif of flashing QRs is given.

### Solution

1. Opening the `gif` as a pdf showed the different frames
2. Scanning each frame gives a character, when put together will give the flag

### Flag

```
KCTF{QR_code_got_evolved_from_static_to_dynamic}
```
