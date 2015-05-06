#define _GNU_SOURCE
#include "bank.h"
#include "ports.h"
#include "util/hash_table.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>
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
    bank->ht_bal = hash_table_create(10);
    bank->ht_salts = hash_table_create(10);

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

    unsigned char iv[16] = {0};

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

    unsigned char iv[16] = {0};

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

    strtok(command, "\n");

    char **command_tokens = {0};
    int numArgs = 0;
    numArgs = tokenize_command(command, &command_tokens);

    if(strcmp("create-user",command_tokens[0]) == 0){
        if(numArgs == 4 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0
            && compare_str_to_regex(command_tokens[2],"[0-9][0-9][0-9][0-9]") > 0
            && compare_str_to_regex(command_tokens[3],"[[:digit:]]+") > 0) {
            
            //printf("create-user\n");

            if(hash_table_find(bank->ht_bal, command_tokens[1]) == NULL){

                char *ptr;
                long amt = strtol(command_tokens[3], &ptr, 10);

                if(amt > INT_MAX) {
                    printf("Usage: create-user <user-name> <pin> <balance>\n");
                } else {

                    char *alocd_bal = NULL;
                    asprintf(&alocd_bal, "%s", command_tokens[3]);
                    char*alocd_user = NULL;
                    asprintf(&alocd_user, "%s", command_tokens[1]);

                    hash_table_add(bank->ht_bal, alocd_user, alocd_bal);

                    //printf("calc iv\n");
                    unsigned char iv[32] = {0};

                    if (!RAND_bytes(iv, sizeof iv)) {
                        printf("Error creating IV\n");
                    }

                    char * alocd_iv = NULL;
                    asprintf(&alocd_iv, "%s", iv);

                    hash_table_add(bank->ht_salts, command_tokens[1], alocd_iv);

                    //printf("calc hash\n");
                    char *hash_out = NULL;
                    hash_pin(command_tokens[2],alocd_iv,&hash_out);
                    
                    //printf("final hash: %s\n", hash_out);

                    char * card_file_name = NULL;
                    asprintf(&card_file_name, "%s%s", command_tokens[1], ".card");

                    FILE *cardFile;
                    cardFile = fopen(card_file_name, "w");

                    int results = fputs(hash_out, cardFile);
                    if (results == EOF) {
                        printf("Error creating card file for user %s", command_tokens[1]);
                        //TODO: ROLL BACK CHANGES!
                    }
                    fclose(cardFile);
                    
                    insane_free(hash_out);
                    insane_free(card_file_name);

                    printf("Created user %s\n", command_tokens[1]);
                }

            } else {
                printf("Error: user %s already exists\n", command_tokens[1]);
            }

        } else {
            printf("Usage: create-user <user-name> <pin> <balance>\n");
        }
    } else if(strcmp("deposit", command_tokens[0]) == 0 ) {
        if(numArgs == 3 && compare_str_to_regex(command_tokens[1], "[a-zA-Z]+") > 0 && compare_str_to_regex(command_tokens[2], "[0-9]+") > 0) {

            if(hash_table_find(bank->ht_bal, command_tokens[1]) == NULL) {
                printf("No such user\n");
            } else {

                char *ptr;
                long amt = strtol(command_tokens[2], &ptr, 10);
                int cur_bal = atoi(hash_table_find(bank->ht_bal, command_tokens[1]));

                if(amt + cur_bal >= INT_MAX || amt + cur_bal < 0) {
                printf("Too rich for this program\n");
                } else {
                    int new_bal = amt + cur_bal;

                    char *alocd_bal = NULL;
                    asprintf(&alocd_bal, "%d", new_bal);
                    char*alocd_user = NULL;
                    asprintf(&alocd_user, "%s", command_tokens[1]);

                    hash_table_del(bank->ht_bal, command_tokens[1]);
                    hash_table_add(bank->ht_bal, alocd_user, alocd_bal);
                    printf("$%d deposited\n", amt);
                }

            }
        }
    } else if(strcmp("balance", command_tokens[0])== 0) {
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1], "[a-zA-Z]+") > 0) {

            if(hash_table_find(bank->ht_bal, command_tokens[1]) == NULL) {
                printf("No such user\n");
            } else {
                int cur_bal = atoi(hash_table_find(bank->ht_bal, command_tokens[1]));
                printf("$%d\n", cur_bal);
            }
        } else {
            printf("Usage: balance <user-name>\n");
        }
    } else if(strcmp("withdraw", command_tokens[0]) == 0) {
        if(numArgs == 3 && compare_str_to_regex(command_tokens[1], "[a-zA-Z]+") > 0 && compare_str_to_regex(command_tokens[2], "[0-9]+") > 0) {

            char *ptr;
            long amt = strtol(command_tokens[2], &ptr, 10);
            int cur_bal = atoi(hash_table_find(bank->ht_bal, command_tokens[1]));

            if(cur_bal - amt < 0) {
                printf("Insufficient funds\n");
            } else {
                int new_bal = cur_bal - amt;

                char *alocd_bal = NULL;
                asprintf(&alocd_bal, "%d", new_bal);
                char*alocd_user = NULL;
                asprintf(&alocd_user, "%s", command_tokens[1]);

                hash_table_del(bank->ht_bal, command_tokens[1]);
                hash_table_add(bank->ht_bal, alocd_user, alocd_bal);

                printf("$%d dispensed\n", amt);
            }

        } else {
            printf("Usage: withdraw <amt>\n");
        }
    } else {
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

    unsigned char* received_message = NULL;
    unsigned char* decrypted_msg = NULL;
    if(verify_and_decrypt_msg(command, bank->key, &decrypted_msg) == 1){
        //printf("received:%s(len: %d)\ndecrypted successfully:%s\n", command, strlen(command), decrypted_msg);
    } else {
        printf("couldn't decrypt:%s (len: %d)\n", command, strlen(command));
        bank_respond_encrypted(bank, "null decrypted message");
        return;
    }
	
    //printf("bank received dmsg: %s\n", decrypted_msg);

    strtok(decrypted_msg, "\n");

    char copy_of_dmsg[strlen(decrypted_msg)+1];
    strncpy(copy_of_dmsg,decrypted_msg,strlen(decrypted_msg));
    copy_of_dmsg[strlen(decrypted_msg)] = '\0';

    char **command_tokens = {0};
    int numArgs = 0;
    numArgs = tokenize_command(copy_of_dmsg, &command_tokens);

    if(strcmp("withdraw",command_tokens[0]) == 0){
        if(numArgs == 3 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0
            && compare_str_to_regex(command_tokens[2],"[[:digit:]]+") > 0) {
            int cur_bal = atoi(hash_table_find(bank->ht_bal, command_tokens[1]));
            int withdrawing = atoi(command_tokens[2]);

            char ret_str[26];

            if(cur_bal - withdrawing >= 0){
                cur_bal = cur_bal - withdrawing;
                char *amt = NULL;
                asprintf(&amt, "%d", cur_bal);
                hash_table_add(bank->ht_bal, command_tokens[1], amt);
                sprintf(ret_str, "%d dispensed\n", withdrawing);
                bank_respond_encrypted(bank, ret_str);
            } else {
                sprintf(ret_str, "Insufficient funds\n");
                bank_respond_encrypted(bank, ret_str);
            }
        } else {
            
        }
    } else if(strcmp("balance",command_tokens[0]) == 0){
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0) {

        } else {
            printf("Usage: balance <user-name>\n");
        }
    } else if(strcmp("begin-session",command_tokens[0]) == 0){
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0) {
            if(hash_table_find(bank->ht_bal, command_tokens[1]) == NULL){
                bank_respond_encrypted(bank, "No such user\n");
            } else {
                char * iv_to_send = NULL;
                asprintf(&iv_to_send, "%s", hash_table_find(bank->ht_salts,command_tokens[1]));
                bank_respond_encrypted(bank, iv_to_send);
            }
        } else {
            printf("Usage: balance <user-name>\n");
        }
    } else{
        printf("Invalid command\n");
        bank_respond_encrypted(bank, "invalid");
        dprint("Invalid command: %s", decrypted_msg);
    }


}
