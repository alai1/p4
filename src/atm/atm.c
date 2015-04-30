#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>


int encrypt_stuff(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  printf("ctx\n");
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
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) printf("encrypt update failed\n");

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
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    printf("decryptupdate failed\n");
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) printf("decrypt update failed\n");
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int compose_message(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char **composed_message){

    unsigned char ciphertext[2048] = "\0";
    int ciphertext_len = encrypt_stuff(plaintext, plaintext_len, key, iv, ciphertext);


    /*HMAC(AES_256_CBC(p,k,iv);iv);AES_256_CBC(p,k,iv);iv
    
     \____________32_____________/1\__ciphertext_len_/1\32      

    */
    //unsigned char composed[32 + 1 + ciphertext_len + 1 + 32];
    unsigned char* composed;

    unsigned char* hmac;

    char * data = NULL;
    asprintf(&data, "%s%s%s", ciphertext, ";", iv);

    hmac = HMAC(EVP_sha256(), key, 32, data, strlen(data), NULL, NULL);

    printf("data to hmac:%s\n", data);
    printf("hmac(data):%s\n", hmac);

    asprintf(&composed, "%s%s%s",hmac,";",data);

    *composed_message = composed;

    return strlen(*composed_message);

}

int verify_and_decrypt_msg(unsigned char *composed_message, unsigned char *key, unsigned char **decrypted){

    char **msg_parts = "";
    int num_msg_parts = 0;
    num_msg_parts = split_string(composed_message, ";", &msg_parts);

    char *expected_hmac = msg_parts[0];
    char *ciphertext = msg_parts[1];
    char *iv = msg_parts[2];
    
    unsigned char *computed_hmac;
    char * cipher_semi_iv = NULL;
    asprintf(&cipher_semi_iv, "%s%s%s", ciphertext, ";", iv);
    computed_hmac = HMAC(EVP_sha256(), key, 32, cipher_semi_iv, strlen(cipher_semi_iv), NULL, NULL);

    if(strcmp(computed_hmac,expected_hmac) != 0){
        return -1;
    }


    unsigned char plaintext[2048] = "\0";
    int plaintext_len = decrypt_stuff(ciphertext, strlen(ciphertext), key, iv, plaintext);

    plaintext[plaintext_len] = '\0';

    *decrypted = plaintext;
    return 1;
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

ATM* atm_create()
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
    // TODO set up more, as needed

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command)
{



    // TODO: Implement the ATM's side of the ATM-bank protocol

	/*
	 * The following is a toy example that simply sends the
	 * user's command to the bank, receives a message from the
	 * bank, and then prints it to stdout.
	 */

    printf("No ATM implementation\n");
	
     //We're using EVP_aes_256_gcm
    unsigned char iv[16] = "";

    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error creating IV\n");
    }

    char recvline[10000];
    int n;

    unsigned char* composed_message;
    unsigned char* decomposed_message;

    int cml = 0;
    cml = compose_message(command, strlen(command), atm->key, iv, &composed_message);

    printf("composed_message: %s\ncml: %d\n", composed_message, cml);
    verify_and_decrypt_msg(composed_message, atm->key, &decomposed_message);

    printf("decomposed_message: %s\n", decomposed_message);

    atm_send(atm, command, strlen(command));
    n = atm_recv(atm,recvline,10000);
    recvline[n]=0;
    fputs(recvline,stdout);
	
}
