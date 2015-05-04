/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include "atm.h"
#include <stdio.h>
#include <stdlib.h>

static const char prompt[] = "ATM: ";

int main(int argc, char**argv)
{

    FILE *atmFile;
    char * fileExtension;
    long length = 0;

    unsigned char * key = NULL;

    if(argv[1] == NULL){
      printf("Error opening ATM initialization file\n");
      return 64;
    }

    atmFile = fopen(argv[1], "r");
    if((fileExtension = strrchr(argv[1],'.')) != NULL ) {
        if(strcmp(fileExtension,".atm") == 0 && atmFile) {
              fseek (atmFile, 0, SEEK_END);
              length = ftell (atmFile);
              fseek (atmFile, 0, SEEK_SET);
              key = malloc (length);
              if (key)
              {
                fread (key, 1, length, atmFile);
              }
              fclose (atmFile);
        } else {
            printf("Error opening ATM initialization file\n");
            return 64;
        }
    }

    char user_input[1000];

    ATM *atm = atm_create();

    atm->key = key;

    if(strcmp(atm->cur_user, "") == 0) {
      printf("%s", prompt);
    } else {
      printf("ATM (%s):", atm->cur_user);
    }
    fflush(stdout);

    while (fgets(user_input, 10000, stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        if(strcmp(atm->cur_user, "") == 0) {
          printf("%s", prompt);
        } else {
          printf("ATM (%s):", atm->cur_user);
        }
        fflush(stdout);
    }
    return EXIT_SUCCESS;
}
