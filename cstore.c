#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cstore_foo.c"


int main(int argc, char *argv[] ) {

    char    *ArchFilename = "archive";
    char    *InputFilename = "test.txt";
    char    *InputFilename1 = "test0.txt";
    char    *InputFilename2 = "test1.pdf";
    char    *pwd = "rv12345";

    if( argc == 2 ) {
        printf("The argument supplied is %s\n", argv[1]);
        
        EncodeFile(ArchFilename, InputFilename, pwd); 
        EncodeFile(ArchFilename, InputFilename2, pwd);
        EncodeFile(ArchFilename, InputFilename1, pwd);    
    
        DecodeFile(ArchFilename, InputFilename, pwd);
        DecodeFile(ArchFilename, InputFilename2, pwd);
        DecodeFile(ArchFilename, InputFilename1, pwd);

        DeleteFromArch(ArchFilename, InputFilename2, pwd);

        ListFiles(ArchFilename);
    }

                
    
    
       
    
     
    return 0;
}