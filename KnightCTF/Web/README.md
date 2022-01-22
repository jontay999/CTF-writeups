# KnightCTF 2022 – Web Challenges

Gonna do very brief description of solve process.

## Challenge 1: Sometimes you need to look way back (25 points)

- Inspecting source code showed that there was a link to a github repository
- Looking at previous commits will give the flag

## Challenge 2: Do something special (50 points)

- A link on the website is given to grab the flag but no result returned
- The special characters in the link need to be url encoded safely

## Challenge 3: Obfuscation isn't enough (50 points)

- In the source code, there is an obfuscated function
- Running the function in terminal will show the path to get the flag

## Challenge 4: Zero is not the limit (50 points)

- Website shows a json with list of users and their info
- Going to the path `/users/1` where 1 is the userId returns the individual users' information
- Going to `/users/-1` retrieves the flag

## Challenge 5: My PHP Site (50 points)

- Website link is index.html
- Url has a file parameter that is used to retrieve pages (LFI)
- passing `?file=index.php` returns an error which probably meant it was filtered out
- Using `?file=php://filter/convert.base64-encode/resource=index.php` returned the base64 encoded version of the source which gave the path to the actual flag

## Challenge 6: Most Secure Calculator 1 (50 points)

- Website has an input where it is straight up evaluated (php)
- Running `system('cat *')` returned the flag

## Challenge 7: Find Pass Code - 2 (150 points)

- Similarly putting `/?source` showed the source code of the file
- The password has to begin with 0e... and has to md5 hash to another 0e result which is another type juggling with magic hashes
- I found some common hashes [here](https://blog.csdn.net/u013512548/article/details/108213295) and it gave the flag
