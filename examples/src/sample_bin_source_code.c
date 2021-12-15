/** ***********************************************
 * File Name : test.c
 * Author    : rootkiter
 * E-mail    : rootkiter@rootkiter.com
 * Created   : 2021-12-09 18:23:20 CST
************************************************* */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int table_key  = 0xdeadbeef;

char *prepare_enc_data() {
    char *pbuf = (char*)malloc(200);
    memset(pbuf, 0, 200);
    memcpy(pbuf, "\x41\x4C\x41\x0C\x41\x4A\x43\x4C\x45\x47\x4F\x47\x0C\x41\x4D\x4F\x22", 40);
    return pbuf;
}

char *decrypt(char *p_enc) {
    int i = 0;
    char k1, k2, k3, k4;
    k1 = table_key & 0xff,
    k2 = (table_key >> 8) & 0xff,
    k3 = (table_key >> 16) & 0xff,
    k4 = (table_key >> 24) & 0xff;

    for (i=0; i<200; i++) {
        if(p_enc[i] == 0) {
            break;
        }
        p_enc[i] ^= k1;
        p_enc[i] ^= k2;
        p_enc[i] ^= k3;
        p_enc[i] ^= k4;
    }
    return p_enc;
}

int main(){
    char *p_enc = prepare_enc_data();
    decrypt(p_enc);
    printf("%s\n", p_enc);
    return 1;
}
