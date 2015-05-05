#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include "aux_functions.h"


#define MAX_OUTPUT 20
#define DEBUG_MODE 1

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
    char msgbuf[100];

    /* Compile regular expression */
    reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Could not compile regex\n");
        exit(1);
    }

    /* Execute regular expression */
    reti = regexec(&regex, str, 0, NULL, 0);
    if (!reti) {
        return 1;
        fprintf(stderr, "Match\n");
    }
    else if (reti == REG_NOMATCH) {
        fprintf(stderr, "%s does not match \n", str);
        return 0;
    }
    else {
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        fprintf(stderr, "Regex match failed: %s\n", msgbuf);
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

    ////printf("plaintext to encrypt: %s\n", plaintext);

    unsigned char ciphertext[2048] = "\0";
    int ciphertext_len = encrypt_stuff(plaintext, plaintext_len, key, iv, ciphertext);

 	ciphertext[ciphertext_len] = '\0';

    ////printf("ciphertext: %s\n", ciphertext);

    /*HMAC(AES_256_CBC(p,k,iv);iv);AES_256_CBC(p,k,iv);iv
    
     \____________32_____________/1\__ciphertext_len_/1\32      

    */
    //unsigned char composed[32 + 1 + ciphertext_len + 1 + 32];
    unsigned char* composed;

    //unsigned char* hmac;

    char * data = NULL;
    asprintf(&data, "%s%s%s", ciphertext, "POOPNUGGET", iv);

    ////printf("cipher semi iv: %s\n", data);

    unsigned char hmac[32] = "\0";
    int iLen;

    ////printf("using key:%s\n", key);
    HMAC(EVP_sha256(), key, 32, data, strlen(data), hmac, &iLen);

    hmac[iLen] = '\0';

    ////printf("hmac(cipher semi iv):%s\n", hmac);

    asprintf(&composed, "%s%s%s",hmac,"POOPNUGGET",data);

    *composed_message = composed;

    ////printf("composed message:%s\n", *composed_message);

    return strlen(*composed_message);

}

int verify_and_decrypt_msg(unsigned char *composed_message, unsigned char *key, unsigned char **decrypted){

    ////printf("composed_message: %s\n", composed_message);

    char **msg_parts = "";
    int num_msg_parts = 0;
    msg_parts = str_split(composed_message, "POOPNUGGET");

    char *expected_hmac = msg_parts[0];
    char *ciphertext = msg_parts[1];
    char *iv = msg_parts[2];

    ////printf("expected_hmac: %s\n", expected_hmac);
    ////printf("ciphertext: %s\n", ciphertext);
    ////printf("iv: %s\n", iv);
    
    char * cipher_semi_iv = NULL;
    asprintf(&cipher_semi_iv, "%s%s%s", ciphertext, "POOPNUGGET", iv);

    ////printf("cipher_semi_iv: %s\n", cipher_semi_iv);


	char someThingIsSeverelyBrokenInMemoryDontDelete[255] = "";

    unsigned char computed_hmac[32] = "\0";
    int iLen;
    ////printf("using key:%s\n", key);
    HMAC(EVP_sha256(), key, 32, cipher_semi_iv, strlen(cipher_semi_iv), computed_hmac, &iLen);

    computed_hmac[iLen] = '\0';

    ////printf("computed_hmac: %s\n", computed_hmac);

    if(strcmp(computed_hmac,expected_hmac) != 0){
        ////printf("verify and decrypt fail! expected %s doesn't match computed_hmac %sfuck!\n", expected_hmac, computed_hmac);
        return -1;
    }


    unsigned char plaintext[2048] = "\0";
    int plaintext_len = decrypt_stuff(ciphertext, strlen(ciphertext), key, iv, plaintext);

    plaintext[plaintext_len] = '\0';
    
    *decrypted = plaintext;

    return 1;
}

/*
example usage:
    char *hash_out = NULL;
    hash_pin(command_tokens[2],iv,&hash_out);
*/

void hash_pin(char *pin, char*iv, char **hash_out){
    char * data = NULL;
    asprintf(&data, "%s%s%s", iv, ";", pin);

    char obuf[33] = "\0";

    char *cur_hash;

    int z;
    for(z = 0; z < 7; z++){
        SHA256(data, strlen(data), obuf);
        asprintf(&cur_hash, "%s", obuf);
        data = cur_hash;
    }
    asprintf(hash_out, "%s", cur_hash);
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
