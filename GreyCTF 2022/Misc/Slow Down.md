# Misc - Slow Down (346)

## Challenge

```c++
/* g++-6 chall.cpp -o chall */
#include <iostream>
#include <unordered_map>
#include <ctime>
#include <string>
using namespace std;

#define LIMIT 25000

string flag = "<REDACTED>";


int main() {
    // Ignore these two lines
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    long long count = 0;
    // id => price
    unordered_map<long long, int> map;

    cout << "Blazinn fazz hashmapp price tracker" << endl;
    cout << "I'll give you something nice if it's too slow" << endl;

    double time = 0;
    int op = LIMIT;
    long long sum;
    while (op--) {
        int action; cin >> action;

        clock_t begin;

        switch (action) {

            case 0:
                long long id; int amount;
                cin >> id >> amount;
                if (count == LIMIT) {
                    cout << "This is too much..." << endl;
                    break;
                }
                count++;

                begin = clock();
                map[id] = amount;
                time += (double) (clock() - begin) / CLOCKS_PER_SEC;

                break;

            case 1:
                sum = 0;

                begin = clock();
                for (auto &item : map) {
                    sum += item.second;
                }
                time += (double) (clock() - begin) / CLOCKS_PER_SEC;

                cout << "The total amount is " << sum << endl;

                break;

            case 2:
                cout << "The total time is " << time << endl;
        }

        if (time > 5.0) {
            cout << flag << endl;
            return 1;
        }
    }
}
```

This was quite a fun challenge, we are basically given an option to make up to 25000 key value inserts into an unordered map (techncially summing up too but it can be ignored for the purposes of this challenge). We are supposed to force the cumulative time of these inserts to be more than 5 seconds. For normal key/value pairs, this will never exceed the time limit and would average around 3 to 4 seconds total.

Unordered maps are basically implementations of hash tables, using collision chaining to resolve hash collisions. Our goal then is to continually insert numbers that will hash to the same bucket, so it will be practically quadratic time and thus exceed the 5 second limit.

A helpful blog post on codeforces [here](https://codeforces.com/blog/entry/62393) details the concept quite nicely so do check that out. The prime numbers listed there don't work but if we check out the primes used in the hashtable implementation in the `gcc` repo [here](https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/src/shared/hashtable-aux.cc), we can just try all the primes relatively near the size of the elements that we are trying, `[~10k - ~25k]`. There seems to be more than 1 answer that would work `20753` and `10273`.

## Solution

```python
prime = 10273
p = remote(host, port)
p.recvuntil(b'slow\n')
inserts = 20000 # didn't actually need 25k inserts in the end
for i in range(inserts):
    payload = f'0 {str(i*prime)} {str(i)}'.encode()
    p.sendline(payload)
p.sendline(b'2')
p.interactive()
p.close()
```

## Flag

```
grey{h4sHmaP5_r_tH3_k1nG_of_dAt4_strUcTuRe5}
```
