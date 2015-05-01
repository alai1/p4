#include "bank.h"
#include "ports.h"
#include "util/hash_table.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "aux_functions.h"



int tokenize_command(char *str, char ***argsOut){

    return split_string(str, " ", argsOut);

}

Bank* bank_create()
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    // TODO set up more, as needed
    bank->ht = hash_table_create(10);

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

/**
* The bank sends encrypted response and expects no further communication
*/
void bank_respond_encrypted(Bank *bank, unsigned char* msg_in)
{
    char recvline[10000];
    int n;

    unsigned char* composed_message;

    unsigned char iv[16] = "";

    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error creating IV\n");
    }

    compose_message(msg_in, strlen(msg_in), bank->key, iv, &composed_message);

    ////printf("bank ready to send:%s\n", composed_message);

    bank_send(bank, composed_message, strlen(composed_message));
}

void bank_send_rcv_encrypted(Bank *bank, unsigned char* msg_in, unsigned char** received)
{
    char recvline[10000];
    int n;

    unsigned char* composed_message;

    unsigned char iv[16] = "";

    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error creating IV\n");
    }

    compose_message(msg_in, strlen(msg_in), bank->key, iv, &composed_message);

    ////printf("bank ready to send:%s\n", composed_message);

    bank_send(bank, composed_message, strlen(composed_message));

    ////printf("bank sent:%s\n", composed_message);
    n = bank_recv(bank,recvline,10000);
    recvline[n]=0;
    ////printf("bank received %d bytes\n", n);
    ////printf("bank recvline:%s\n", recvline);
    *received = recvline;
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{

    char **command_tokens = "";
    int numArgs = 0;
    numArgs = tokenize_command(command, &command_tokens);

    if(strcmp("create-user",command_tokens[0]) == 0){
        if(numArgs == 4 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0
            && compare_str_to_regex(command_tokens[2],"[0-9][0-9][0-9][0-9]") > 0
            && compare_str_to_regex(command_tokens[3],"[[:digit:]]+") > 0) {

            hash_table_add(bank->ht, command_tokens[1], command_tokens[3]);

        } else {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
        }
    } else{
        printf("Invalid command\n");
    }
   
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{

    // TODO: Implement the bank side of the ATM-bank protocol

	/*
	 * The following is a toy example that simply receives a
	 * string from the ATM, prepends "Bank got: " and echoes 
	 * it back to the ATM before printing it to stdout.
	 */

    unsigned char* received_message;
    unsigned char* decrypted_msg;
    if(verify_and_decrypt_msg(command, bank->key, &decrypted_msg) == 1){
        ////printf("received:%s\ndecrypted successfully:%s", command, decrypted_msg);
    } else {
        ////printf("hmacs don't match\n");
    }
	
    char copy_of_dmsg[strlen(decrypted_msg)+1];
    strncpy(copy_of_dmsg,decrypted_msg,strlen(decrypted_msg));
    copy_of_dmsg[strlen(decrypted_msg)] = '\0';


    char **command_tokens = "";
    int numArgs = 0;
    numArgs = tokenize_command(copy_of_dmsg, &command_tokens);

    if(strcmp("deposit",command_tokens[0]) == 0){
        if(numArgs == 3 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0
            && compare_str_to_regex(command_tokens[2],"[[:digit:]]+") > 0) {
                printf("%s %s %s\n", command_tokens[0], command_tokens[1], command_tokens[2]);
        } else {
            printf("Usage:  deposit <user-name> <amt>\n");
        }
    } else if(strcmp("balance",command_tokens[0]) == 0){
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0) {
            printf("%s %s \n", command_tokens[0], command_tokens[1]);
        } else {
            printf("Usage:  balance <user-name>\n");
        }
    } else if(strcmp("begin-session",command_tokens[0]) == 0){
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0) {
            if(hash_table_find(bank->ht, command_tokens[0]) == NULL){
                char * cipher_semi_iv = NULL;
                bank_respond_encrypted(bank, "No such user");
            }
        } else {
            printf("Usage:  balance <user-name>\n");
        }
    } else{
        printf("Invalid command\n");
    }


}
