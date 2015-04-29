#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

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

int tokenize_command(char *str, char ***argsOut){
char *  p    = strtok (str, " ");
int n_spaces = 0;

char **argumentsOut = NULL;
/* split string and append tokens to 'argumentsOut' */

while (p) {
  argumentsOut = realloc (argumentsOut, sizeof (char*) * ++n_spaces);

  if (argumentsOut == NULL)
    exit (-1); /* memory allocation failed */

  argumentsOut[n_spaces-1] = p;

  p = strtok (NULL, " ");
}

/* realloc one extra element for the last NULL */

argumentsOut = realloc (argumentsOut, sizeof (char*) * (n_spaces+1));
argumentsOut[n_spaces] = 0;

*argsOut = argumentsOut;

return n_spaces;

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

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    char **command_tokens = "";
    int numArgs = 0;
    numArgs = tokenize_command(command, &command_tokens);

    if(strcmp("create-user",command_tokens[0]) == 0){
        if(numArgs == 4 && compare_str_to_regex(command_tokens[1],"[a-zA-Z]+") > 0
            && compare_str_to_regex(command_tokens[2],"[0-9][0-9][0-9][0-9]") > 0
            && compare_str_to_regex(command_tokens[3],"[[:digit:]]+") > 0) {
                printf("%s %s %s %s\n", command_tokens[0], command_tokens[1], command_tokens[2] , command_tokens[3]);
        } else {
            printf("Usage:  create-user <user-name> <pin> <balance>");
        }
    } else{
        printf("Invalid command\n");
    }
   
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    

    char **command_tokens = "";
    int numArgs = 0;
    numArgs = tokenize_command(command, &command_tokens);

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
    } else{
        printf("Invalid command\n");
    }

    // TODO: Implement the bank side of the ATM-bank protocol

	/*
	 * The following is a toy example that simply receives a
	 * string from the ATM, prepends "Bank got: " and echoes 
	 * it back to the ATM before printing it to stdout.
	 */

	
    char sendline[1000];
    command[len]=0;
    sprintf(sendline, "Bank got: %s", command);
    bank_send(bank, sendline, strlen(sendline));
    printf("Received the following:\n");
    fputs(command, stdout);
	



}
