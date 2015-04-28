#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

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
    
char bankFileName[255] = "";
snprintf(bankFileName, sizeof bankFileName, "%s%s", argv[1], ".bank");

char atmFileName[255] = "";
snprintf(atmFileName, sizeof atmFileName, "%s%s", argv[1], ".atm");

char someThingIsSeverelyBrokenInMemoryDontDelete[255] = "";
/*If you delete it, when you create unsigned key[1] and then do the random bytes function,
you get a random byte with atmFileName appended to the end! e.g. "A0keys.atm" No matter
what the key size it would always append atmFileName to it.

I spent like 3 hours trying to figure out why this was happening and I think it has something
to do will null pointers or something but I have no idea why its broken. Putting a variable on
the stack between them fixed it. HOLY FUCK.
*/

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



printf("Successfully initialized bank state\n");

    return 0;
}