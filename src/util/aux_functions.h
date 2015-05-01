#include <regex.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

int compare_str_to_regex(char* str, const char *pattern);
int split_string(char *str, const char* separator, char ***argsOut);
int encrypt_stuff(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);
int decrypt_stuff(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);
int compose_message(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char **composed_message);
int verify_and_decrypt_msg(unsigned char *composed_message, unsigned char *key, unsigned char **decrypted);
char **str_array_append(char **array, size_t nitems, const char *item, 
                        size_t itemlen);
void str_array_free(char **array);
char **str_split(const char *input, const char *sep);
size_t str_array_len(char **array);