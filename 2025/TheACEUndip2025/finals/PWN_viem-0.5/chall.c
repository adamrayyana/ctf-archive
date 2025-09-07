#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct viem_lite_t {
    char ram[0x1000];
    int rip;
    int rsp;
} viem_lite;

int main(){
    int i;
    viem_lite vl;
    memset((void*)&vl, 0, sizeof(viem_lite));
    vl.rip = 0;

    for (i = 0; i < sizeof vl.ram; i++){
        switch (getchar()) {
            case 'a': vl.ram[i] = 'a'; break;
            case 'b': vl.ram[i] = 'b'; break;
            case 'c': vl.ram[i] = 'c'; break;
            case '\n': break;
        }
    }
    
    vl.rsp = i;

    while(1){
        switch (vl.ram[vl.rip]) {
            case 'a': {
                vl.ram[--vl.rsp] = getchar();
                vl.ram[--vl.rsp] = getchar();
                break;
            }
            case 'b': {
                putchar(vl.ram[vl.rsp++]);
                putchar(vl.ram[vl.rsp++]);
                break;
            }
            case 'c': return 0;
        }
        vl.rip++;
    }

}

__attribute__((constructor)) void init(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}