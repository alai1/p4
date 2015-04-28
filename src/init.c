#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

int main(int argc, char *argv[]) {

FILE *wordsfile, *plaintextfile, *ciphertextfile, *tempfile;
    
char bankFile[255];
snprintf(bankFile, sizeof buf, "%s%s", argv[1], ".bank");

char atmFile[255];
snprintf(bankFile, sizeof buf, "%s%s", argv[1], ".atm");

unsigned char key[16], iv[16];

if (!RAND_bytes(key, sizeof key)) {
    /* OpenSSL reports a failure, act accordingly */
}
if (!RAND_bytes(iv, sizeof iv)) {
    /* OpenSSL reports a failure, act accordingly */
}

    return 0;
}