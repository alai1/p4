/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";

int main(int argc, char**argv)
{
   int n;
   char sendline[1000];
   char recvline[1000];

   unsigned char * key = NULL;

   Bank *bank = bank_create();

    FILE *bankFile;
    char * fileExtension;
    long length = 0;

    if(argv[1] == NULL){
      printf("Error opening bank initialization file\n");
      return 64;
    }

    bankFile = fopen(argv[1], "r");
    if((fileExtension = strrchr(argv[1],'.')) != NULL ) {
        if(strcmp(fileExtension,".bank") == 0 && bankFile) {
              fseek (bankFile, 0, SEEK_END);
              length = ftell (bankFile);
              fseek (bankFile, 0, SEEK_SET);
              key = malloc (length);
              if (key)
              {
                fread (key, 1, length, bankFile);
              }
              fclose (bankFile);
        } else {
            printf("Error opening bank initialization file\n");
            return 64;
        }
    }

   printf("%s", prompt);
   fflush(stdout);

   bank->key = key;

   while(1)
   {
       fd_set fds;
       FD_ZERO(&fds);
       FD_SET(0, &fds);
       FD_SET(bank->sockfd, &fds);
       select(bank->sockfd+1, &fds, NULL, NULL, NULL);

       if(FD_ISSET(0, &fds))
       {
           fgets(sendline, 10000,stdin);
           bank_process_local_command(bank, sendline, strlen(sendline));
           printf("%s", prompt);
           fflush(stdout);
       }
       else if(FD_ISSET(bank->sockfd, &fds))
       {
           n = bank_recv(bank, recvline, 10000);
           bank_process_remote_command(bank, recvline, n);
       }
   }

   return EXIT_SUCCESS;
}
