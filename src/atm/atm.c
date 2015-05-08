#define _GNU_SOURCE
#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "aux_functions.h"

#define insane_free(p) { free(p); p = 0; }


int tokenize_command(char *str, char ***argsOut){

    return split_string(str, " ", argsOut);

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

    atm->cur_user = "";

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

int atm_send_rcv_encrypted(ATM *atm, unsigned char* msg_in, unsigned char** received)
{
    char recvline[10000];
    int n = 0;
    int composed_message_len = 0;

    unsigned char* composed_message;

    unsigned char iv[16] = {0};

    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error creating IV\n");
    }

    // printf("atm sending plaintext: %s\n", msg_in);
    composed_message_len = compose_message(msg_in, strlen(msg_in), atm->key, iv, &composed_message);

    atm_send(atm, composed_message, composed_message_len);

    n = atm_recv(atm,recvline,10000);

    *received = recvline;
    return n;

}

void atm_process_command(ATM *atm, char *command)
{
    int recvd_len = 0;
    strtok(command, "\n");

    char copy_of_command[strlen(command)+1];
    strncpy(copy_of_command,command,strlen(command));
    copy_of_command[strlen(command)] = '\0';

    char *msg_plaintext = NULL;

    unsigned char* received_message = NULL;
    unsigned char* decrypted_msg = NULL;

    char **command_tokens = {0};
    int numArgs = 0;
    
    numArgs = tokenize_command(copy_of_command, &command_tokens);


    if(strcmp("begin-session",command_tokens[0]) == 0){
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1], "^[a-zA-Z]+$") > 0) {
            ////printf("%s %s\n", command_tokens[0], command_tokens[1]);

            ////printf("about to send and encrypt  %s\n", command);
            char *card_file_name = NULL;
            asprintf(&card_file_name, "%s.card", command_tokens[1]);

            long length = 0;
            char * fileExtension;
            FILE *cardFile;
            unsigned char * card_contents = NULL;

            cardFile = fopen(card_file_name, "r");
            if((fileExtension = strrchr(card_file_name,'.')) != NULL ) {
                if(strcmp(fileExtension,".card") == 0 && cardFile) {
                      fseek (cardFile, 0, SEEK_END);
                      length = ftell (cardFile);
                      fseek (cardFile, 0, SEEK_SET);
                      card_contents = malloc (length);
                      if (card_contents)
                      {
                        fread (card_contents, 1, length, cardFile);
                      }
                } else {
                    //WHOOPS?
                }
            } else {
                printf("Unable to access %s's card\n", command_tokens[1]);
                return;
            }

            // printf("reading card_contents:\n");
            // print_bytes(card_contents, length);
<<<<<<< HEAD
            fclose (cardFile);
=======

>>>>>>> origin/master

            insane_free(card_file_name);
                
            if(strcmp(atm->cur_user, "") != 0) {
                printf("A user is already logged in\n");
            } else {
<<<<<<< HEAD
                recvd_len = atm_send_rcv_encrypted(atm, command, &received_message);
                verify_and_decrypt_msg(received_message, atm->key, &decrypted_msg);
=======
                printf("PIN? ");
                char pin[5];
                if(fgets(pin, 5, stdin) != NULL && compare_str_to_regex(pin, "[0-9][0-9][0-9][0-9]")) {
                    

                    recvd_len = atm_send_rcv_encrypted(atm, command, &received_message);
                    verify_and_decrypt_msg(received_message, atm->key, &decrypted_msg);
>>>>>>> origin/master

                if(strcmp(decrypted_msg, "No such user") == 0) {
                    printf("No such user\n");
                } else {
                    printf("PIN? ");
                    char pin[5];
                    if(fgets(pin, 5, stdin) != NULL && compare_str_to_regex(pin, "^[0-9]+$") > 0) {
                    
                        unsigned char* received_iv = decrypted_msg;


                        char *hashed = NULL;
                        hash_pin(pin, received_iv, &hashed);

                        if(memcmp(hashed, card_contents, 32) == 0) {
                            printf("Authorized\n");

                            char *allocd_cur_user = NULL;
                            asprintf(&allocd_cur_user, "%s", command_tokens[1]);

                            atm->cur_user = allocd_cur_user;
                        } else {
                            printf("Not authorized\n");
<<<<<<< HEAD
                            // printf("hashed:\n");
                            // print_bytes(hashed, 32);
                            // printf("card_contents%d\n");
                            // print_bytes(card_contents, 32);
=======
                            printf("hashed:\n");
                            print_bytes(hashed, 32);
                            printf("card_contents%d\n");
                            print_bytes(card_contents, 32);
>>>>>>> origin/master
                        }

                        insane_free(decrypted_msg);

                    } else {
                        printf("Not authorized\n");
                    }
                }
            }
            insane_free(card_contents);
        } else {
            printf("Usage: begin-session <user-name>\n");
        }
    } else if(strcmp("balance",command_tokens[0]) == 0) {
        if(numArgs == 1) {
            if(strcmp(atm->cur_user, "") == 0) {
                printf("No user logged in\n");
            } else {
                char *new_command = NULL;
                asprintf(&new_command, "%s %s", command_tokens[0], atm->cur_user);

                atm_send_rcv_encrypted(atm, new_command, &received_message);

                insane_free(new_command);

                verify_and_decrypt_msg(received_message, atm->key, &decrypted_msg);

                printf("%s\n", decrypted_msg);

                insane_free(decrypted_msg);
            }
        } else {
            printf("Usage: balance <user-name>\n");
        }
    } else if(strcmp("withdraw", command_tokens[0])== 0) {
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1], "^[0-9]+$") > 0 && command_tokens[1] >= 0) {
            if(strcmp(atm->cur_user, "") == 0) {
                printf("No user logged in\n");
            } else {
                char *new_command = NULL;
                asprintf(&new_command, "%s %s %s", command_tokens[0], atm->cur_user, command_tokens[1]);

                atm_send_rcv_encrypted(atm, new_command, &received_message);

                //should receive either "Insufficient funds" or "$<amt> dispensed"
                verify_and_decrypt_msg(received_message, atm->key, &decrypted_msg);

                printf("%s\n", decrypted_msg);             
            }
        } else {
            printf("Usage: withdraw <amt>\n");
        }
    } else if(strcmp("end-session", command_tokens[0]) == 0) {
        if(strcmp(atm->cur_user, "") == 0) {
            printf("No user logged in\n");
        } else {
            atm->cur_user = "";
            printf("User logged out\n");
        }
    } else {
        printf("Invalid command\n");
    }

    // atm_send(atm, command, strlen(command));
    // n = atm_recv(atm,recvline,10000);
    // recvline[n]=0;
    // fputs(recvline,stdout);
    
}
