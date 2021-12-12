# niteCTF – Qurious Case

- **Category:** Forensics
- **Points:** 500

## Challenge

We are given a file called `HelloDarknessMyOldFriend.png` that is just a black square.

## Solution

1. Running through the filters in `stegsolve.jar` showed a QR Code that had the top left quarter removed
2. Used a photo editing software to paste in the standard black square on the top left to help QR scanners detect it better
3. Uploaded the image to this [site](https://merricx.github.io/qrazybox/) got me the flag.

```
nite{tH@T'$_qRazzYyYy}
```

## Thoughts

- Luckily there were similar challenges from previous CTFs that I could refer to, otherwise I would have to manually decode it lol
