#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "aux_functions.h"




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

void atm_send_encrypted(ATM *atm, unsigned char* msg_in, unsigned char** received)
{
    char recvline[10000];
    int n;

    unsigned char* composed_message;

    unsigned char iv[16] = "";

    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error creating IV\n");
    }

    compose_message(msg_in, strlen(msg_in), atm->key, iv, &composed_message);

    printf("ready to send:%s\n", composed_message);

    atm_send(atm, composed_message, strlen(composed_message));

    printf("sent:%s\n", composed_message);
    n = atm_recv(atm,recvline,10000);
    recvline[n]=0;
    printf("received %d bytes\n", n);
    printf("recvline:%s\n", recvline);
    *received = recvline;
}

void atm_process_command(ATM *atm, char *command)
{

    char copy_of_command[strlen(command)+1];
    strncpy(copy_of_command,command,strlen(command));
    copy_of_command[strlen(command)] = '\0';

    char *msg_plaintext;

    unsigned char* received_message;
    unsigned char* decrypted_msg;

    char **command_tokens = "";
    int numArgs = 0;
    numArgs = tokenize_command(copy_of_command, &command_tokens);

    if(strcmp("begin-session",command_tokens[0]) == 0){
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0) {
            printf("%s %s\n", command_tokens[0], command_tokens[1]);

            printf("about to send and encrypt  %s\n", command);
            atm_send_encrypted(atm, command, &received_message);


            verify_and_decrypt_msg(received_message, atm->key, &decrypted_msg);
            printf("decrypted received_message: %s\n", decrypted_msg);

        } else {
            printf("Usage:  begin-session <user-name>\n");
        }
    } else if(strcmp("balance",command_tokens[0]) == 0){
        if(numArgs == 2 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0) {
            printf("%s %s \n", command_tokens[0], command_tokens[1]);
        } else {
            printf("Usage:  balance <user-name>\n");
        }
    } else{
        printf("Invalid command\n");
    }



    
    

    // atm_send(atm, command, strlen(command));
    // n = atm_recv(atm,recvline,10000);
    // recvline[n]=0;
    // fputs(recvline,stdout);
	
}
