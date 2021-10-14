#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cstore_foo.c"


int main(int argc, char *argv[] ) {

    char    *ArchFilename;
    char    *InputFilename;
    char    *pwd;

    if( argc >= 3 ) {

        //printf("The first argument supplied is %s\n", argv[1]);
        //printf("The second argument supplied is %s\n", argv[2]);
        //printf("The third argument supplied is %s\n", argv[3]);
        //printf("n args passed %i\n", argc);

        if (strcmp(argv[1], "add")==0){

            if( argc > 5 ) {

                pwd = argv[3];
                ArchFilename = argv[4];
                InputFilename = argv[5];
            
                EncodeFile(ArchFilename, InputFilename, pwd); 
            
            }else{

                printf("arguments incorrectly passed to the program\n");
                exit(1);

            }            

        }else if (strcmp(argv[1], "list")==0){

            if( argc == 3 ) {

                ArchFilename = argv[2];            
                ListFiles(ArchFilename);
            
            }else{

                printf("arguments incorrectly passed to the program\n");
                exit(1);

            }             

        }else if (strcmp(argv[1], "extract")==0){

            if( argc > 5 ) {

                pwd = argv[3];
                ArchFilename = argv[4];
                InputFilename = argv[5];
            
                DecodeFile(ArchFilename, InputFilename, pwd);

            }else{

                printf("arguments incorrectly passed to the program\n");
                exit(1);

            }            
            
        }else if (strcmp(argv[1], "delete")==0){

            if( argc > 5 ) {

                pwd = argv[3];
                ArchFilename = argv[4];
                InputFilename = argv[5];
            
                DeleteFromArch(ArchFilename, InputFilename, pwd);

            }else{

                printf("arguments incorrectly passed to the program\n");
                exit(1);

            }          
            
        }else{

            printf("this command is not implemented in the file store program\n");
            exit(1);

        }
        
    }else{

        printf("arguments incorrectly passed to the program\n");
        exit(1);
    }    
     
    return 0;

}