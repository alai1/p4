#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#define insane_free(p) { free(p); p = 0; }

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

int main(int argc, char *argv[]) {

if ( argc != 2 ){
  printf("Usage:  init <filename>");
  return 62;
}

FILE *bankFile, *atmFile;
    
char *bankFileName = NULL;
asprintf(&bankFileName, "%s%s", argv[1], ".bank");

char *atmFileName = NULL;
asprintf(&atmFileName, "%s%s", argv[1], ".atm");


if( access( bankFileName, F_OK ) != -1 || access( atmFileName, F_OK ) != -1 ) {
    printf("Error:  one of the files already exists");
    return 63;
}

 //We're using EVP_aes_256_gcm
unsigned char key[32] = "";

if (!RAND_bytes(key, sizeof key)) {
    printf("Error creating initialization files\n");
    return 64;
}


bankFile = fopen(bankFileName, "w");

int results = fputs(key, bankFile);
if (results == EOF) {
    printf("Error creating initialization files\n");
    return 64;
}
fclose(bankFile);

atmFile = fopen(atmFileName, "w");

results = fputs(key, atmFile);
if (results == EOF) {
    printf("Error creating initialization files\n");
    return 64;
}
fclose(atmFile);


insane_free(atmFileName);
insane_free(bankFileName);

printf("Successfully initialized bank state\n");

    return 0;
}