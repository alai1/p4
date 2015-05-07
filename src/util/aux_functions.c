
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <regex.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "aux_functions.h"


#define MAX_OUTPUT 20
#define DEBUG_MODE 1

void print_bytes(const void *object, size_t size)
{
  size_t i;

  printf("[ ");
  for(i = 0; i < size; i++)
  {
    printf("%02x ", ((const unsigned char *) object)[i] & 0xff);
  }
  printf("]\n");
}


void dprint(const char *format, ...){
    char * concat = NULL;
    asprintf(&concat, "%s%s", "¯\\_(ツ)_/¯", format);

    va_list args;
    va_start(args, format);
    if(DEBUG_MODE){
      vprintf(concat, args);
    }
    va_end(args);
}

int compare_str_to_regex(char* str, const char *pattern){
    regex_t regex;
    int reti;
    char msgbuf[100] = {0};

    /* Compile regular expression */
    reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti) {
        // fprintf(stderr, "Could not compile regex\n");
        exit(1);
    }

    /* Execute regular expression */
    reti = regexec(&regex, str, 0, NULL, 0);
    if (!reti) {
        return 1;
        // fprintf(stderr, "Match\n");
    }
    else if (reti == REG_NOMATCH) {
        //fprintf(stderr, "%s does not match \n", str);
        return 0;
    }
    else {
        // regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        // fprintf(stderr, "Regex match failed: %s\n", msgbuf);
        return 0;
    }
}

int split_string(char *str, const char* separator, char ***argsOut){
char *  p    = strtok (str, separator);
int n_spaces = 0;

char **argumentsOut = NULL;
/* split string and append tokens to 'argumentsOut' */

while (p) {
  argumentsOut = realloc (argumentsOut, sizeof (char*) * ++n_spaces);

  if (argumentsOut == NULL)
    exit (-1); /* memory allocation failed */

  argumentsOut[n_spaces-1] = p;

  p = strtok (NULL, separator);
}

/* realloc one extra element for the last NULL */

argumentsOut = realloc (argumentsOut, sizeof (char*) * (n_spaces+1));
argumentsOut[n_spaces] = 0;

*argsOut = argumentsOut;

return n_spaces;

}

int encrypt_stuff(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{

  EVP_CIPHER_CTX *ctx;

  int len = 0;

  int ciphertext_len = 0;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) printf("context initialization failed\n");
 
  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    printf("encryption operation initialization failed\n");

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    printf("encryptupdate failed\n");
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) printf("encrypt final failed\n");

  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt_stuff(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) printf("context initialization failed\n");

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    printf("decryption operation initialization failed\n");

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
    printf("decryptupdate failed!\n");
    printf("#failure# ciphertext: %s\n",ciphertext);
    printf("#failure# ciphertext_len: %d\n",ciphertext_len);
    printf("#failure# plaintext: %s\n",plaintext);
  }
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) printf("decrypt final failed\n");
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int compose_message(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char **composed_message){

    char * curr = NULL;

    unsigned char ciphertext[2048] = {0};
    int ciphertext_len = encrypt_stuff(plaintext, plaintext_len, key, iv, ciphertext);


    unsigned char hmac[32] = {0};
    int hmacLen = 0;

    char * cipher_and_iv = NULL;
    cipher_and_iv = calloc(1, ciphertext_len + 16);

    // printf("ciphertext:\n");
    // print_bytes(ciphertext, ciphertext_len);
    // printf("iv:\n");
    // print_bytes(iv, 16);

    memcpy(cipher_and_iv, ciphertext, ciphertext_len);
    memcpy(cipher_and_iv + ciphertext_len, iv, 16);

    // printf("cipher_and_iv:\n");
    // print_bytes(cipher_and_iv, ciphertext_len + 16);

    HMAC(EVP_sha256(), key, 32, cipher_and_iv, ciphertext_len + 16, hmac, &hmacLen);


    // printf("hmac:\n");
    // print_bytes(hmac, hmacLen);

    /*HMAC(AES_256_CBC(p,k,iv);iv);AES_256_CBC(p,k,iv);iv
    
     \____________32_____________/1\__ciphertext_len_/1\16      
    */

    int composed_len = sizeof(hmacLen) + hmacLen + sizeof(ciphertext_len) + ciphertext_len + 16;
    char *composed = NULL;
    composed = calloc(1, composed_len);

    // printf("after calloc composed, composed is %s", composed == NULL ? "null" : "not null");
    // printf("composed_len is %d\n", composed_len);
    // printf("hmac_len is %d\n", hmacLen);

    memcpy(composed, &hmacLen, sizeof(int));
    memcpy(composed + sizeof(hmacLen), hmac, hmacLen);
    memcpy(composed + sizeof(hmacLen) + hmacLen, &ciphertext_len, sizeof(ciphertext_len));
    memcpy(composed + sizeof(hmacLen) + hmacLen + sizeof(ciphertext_len), ciphertext, ciphertext_len);
    memcpy(composed + sizeof(hmacLen) + hmacLen + sizeof(ciphertext_len) + ciphertext_len, iv, 16);

    // printf("after memcpy composed\n");

    *composed_message = composed;

    // printf("composed:\n");
    // print_bytes(composed, composed_len);

    return composed_len;

}

int verify_and_decrypt_msg(unsigned char *composed_message, unsigned char *key, unsigned char **decrypted){

    int expected_hmac_len = 0;
    unsigned char *expected_hmac = NULL;
    int ciphertext_len = 0;
    unsigned char *ciphertext = NULL;
    unsigned char *iv = NULL;

    // printf("about to verify and decrypt:\n");
    // print_bytes(composed_message, composed_len);

    char *curr = composed_message;

    memcpy(&expected_hmac_len, curr, sizeof(int));
    curr += sizeof(int);
    // printf("v&d expected_hmac_len: %d\n", expected_hmac_len);


    expected_hmac = calloc(1, expected_hmac_len);
    memcpy(expected_hmac, curr, expected_hmac_len);
    curr += expected_hmac_len;

    // printf("v&d expected_hmac:\n");
    // print_bytes(expected_hmac, expected_hmac_len);

    memcpy(&ciphertext_len, curr, sizeof(int));
    curr += sizeof(int);


    ciphertext = calloc(1, ciphertext_len);
    memcpy(ciphertext, curr, ciphertext_len);
    curr += ciphertext_len;

    // printf("v&d ciphertext:\n");
    // print_bytes(ciphertext, ciphertext_len);

    iv = calloc(1, 16);
    memcpy(iv, curr, 16);

    // printf("v&d iv:\n");
    // print_bytes(iv, 16);
    
    
    char * cipher_and_iv = NULL;
    cipher_and_iv = calloc(1, ciphertext_len + 16);
    memcpy(cipher_and_iv, ciphertext, ciphertext_len);
    memcpy(cipher_and_iv + ciphertext_len, iv, 16);

    int hmacLen;
    unsigned char computed_hmac[32] = {0};
    HMAC(EVP_sha256(), key, 32, cipher_and_iv, ciphertext_len + 16, computed_hmac, &hmacLen);

    // printf("v&d computed_hmac:\n");
    // print_bytes(computed_hmac, hmacLen);



    if(memcmp(expected_hmac, computed_hmac, 32) != 0){
        ////printf("verify and decrypt fail! expected %s doesn't match computed_hmac %sfuck!\n", expected_hmac, computed_hmac);
        return -1;
    }


    unsigned char plaintext[2048] = {0};
    int plaintext_len = decrypt_stuff(ciphertext, ciphertext_len, key, iv, plaintext);

    plaintext[plaintext_len] = '\0';
    
    char * al_plaintext = NULL;
    asprintf(&al_plaintext, "%s", plaintext);

    // printf("v&d plaintext: %s\n", plaintext);

    *decrypted = al_plaintext;

    return 1;
}

/*
example usage:
    char *hash_out = NULL;
    hash_pin(command_tokens[2],iv,&hash_out);
*/

void hash_pin(char *pin, char*iv, char **hash_out){
    char * data = NULL;
    char * iterator = NULL;
    if(asprintf(&data, "%s%s%s", iv, ";", pin) == -1){
      printf("asprintf failed data:hash\n");
    }

    char obuf[33] = {0};

    char *cur_hash;

    int z;
    for(z = 0; z < 7; z++){
        SHA256(data, strlen(data), obuf);
        if(asprintf(&cur_hash, "%s", obuf) == -1){
          printf("asprintf failed curhash:hash_pin\n");
        }
        iterator = data;
        data = cur_hash;
        insane_free(iterator);
    }
    asprintf(hash_out, "%s", cur_hash);
    insane_free(data);
}


/* Append an item to a dynamically allocated array of strings. On failure,
   return NULL, in which case the original array is intact. The item
   string is dynamically copied. If the array is NULL, allocate a new
   array. Otherwise, extend the array. Make sure the array is always
   NULL-terminated. Input string might not be '\0'-terminated. */
char **str_array_append(char **array, size_t nitems, const char *item, 
                        size_t itemlen)
{
    /* Make a dynamic copy of the item. */
    char *copy;
    if (item == NULL)
        copy = NULL;
    else {
        copy = malloc(itemlen + 1);
        if (copy == NULL)
            return NULL;
        memcpy(copy, item, itemlen);
        copy[itemlen] = '\0';
    }

    /* Extend array with one element. Except extend it by two elements, 
       in case it did not yet exist. This might mean it is a teeny bit
       too big, but we don't care. */
    array = realloc(array, (nitems + 2) * sizeof(array[0]));
    if (array == NULL) {
        free(copy);
        return NULL;
    }

    /* Add copy of item to array, and return it. */
    array[nitems] = copy;
    array[nitems+1] = NULL;
    return array;
}


/* Free a dynamic array of dynamic strings. */
void str_array_free(char **array)
{
    if (array == NULL)
        return;
    for (size_t i = 0; array[i] != NULL; ++i)
        free(array[i]);
    free(array);
}


/* Split a string into substrings. Return dynamic array of dynamically
   allocated substrings, or NULL if there was an error. Caller is
   expected to free the memory, for example with str_array_free. */
char **str_split(const char *input, const char *sep)
{
    size_t nitems = 0;
    char **array = NULL;
    const char *start = input;
    char *next = strstr(start, sep);
    size_t seplen = strlen(sep);
    const char *item;
    size_t itemlen;

    for (;;) {
        next = strstr(start, sep);
        if (next == NULL) {
            /* Add the remaining string (or empty string, if input ends with
               separator. */
            char **new = str_array_append(array, nitems, start, strlen(start));
            if (new == NULL) {
                str_array_free(array);
                return NULL;
            }
            array = new;
            ++nitems;
            break;
        } else if (next == input) {
            /* Input starts with separator. */
            item = "";
            itemlen = 0;
        } else {
            item = start;
            itemlen = next - item;
        }
        char **new = str_array_append(array, nitems, item, itemlen);
        if (new == NULL) {
            str_array_free(array);
            return NULL;
        }
        array = new;
        ++nitems;
        start = next + seplen;
    }

    if (nitems == 0) {
        /* Input does not contain separator at all. */
        assert(array == NULL);
        array = str_array_append(array, nitems, input, strlen(input));
    }

    return array;
}


/* Return length of a NULL-delimited array of strings. */
size_t str_array_len(char **array)
{
    size_t len;

    for (len = 0; array[len] != NULL; ++len)
        continue;
    return len;
}
