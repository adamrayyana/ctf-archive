#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char buf[0x100];
    int len, choice;

    for(;;){
	memset(buf, 0, sizeof(buf));
        printf("1. oct2dec\n");
        printf("2. hex2dec\n");
        printf("> ");
        scanf("%d%*c", &choice);
        switch (choice) {
            case 1:
		printf("len: ");
		scanf("%d%*c", &len);
                printf("input (e.g. 00 ~ 77): ");
                for (int i = 0; i < len; i++) scanf("%02hho", buf + i);
                break;
            case 2:
		printf("len: ");
		scanf("%d%*c", &len);
                printf("input (e.g. 00 ~ ff): ");
                for (int i = 0; i < len; i++) scanf("%02hhx", buf + i);
                break;
            default:
                return 0;
        }
        printf("output: ");
        for (int i = 0; i < len; i++) printf("%d ", (unsigned char)buf[i]);
        printf("\n");
    }

}
