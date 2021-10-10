#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.c"

void EncodeFile(char *InputFilename, char *pwd) { 
    F_DATA          *ClearData;          
    F_DATA          *EncData;          
    char            OutputFilename[PATH_MAX];
    BYTE iv[IV_LEN] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    BYTE            *key0, *key1;

    ClearData = ReadFile(InputFilename);    

    //generate key and IV here pass it to function
    key0 = gen_key(pwd, "confidentiality");
    key1 = gen_key(pwd, "integrity");
    EncData = EncodeData(ClearData, key0, key1, 256, iv);

    strcpy(OutputFilename, InputFilename);
    strcat(OutputFilename, ENCRYPTED_FILE_SUFFIX);

    WriteFile(EncData, OutputFilename);
    //0 and release all data
    memset(ClearData, 0, sizeof(*ClearData));
    memset(EncData, 0, sizeof(*EncData));
    memset(key0, 0, sizeof(*key0));
    memset(key1, 0, sizeof(*key1));
    free(ClearData);
    free(EncData);
    free(key0);
    free(key1);    
}


void DecodeFile(char *InputFilename, char *pwd) {  
    F_DATA          *EncData;          
    F_DATA          *ClearData;          
    char            OutputFilename[PATH_MAX];
    BYTE            iv[IV_LEN];
    BYTE            *key0, *key1;
    
    strcpy(OutputFilename, InputFilename);
    strcat(OutputFilename, ENCRYPTED_FILE_SUFFIX);
    
    EncData = ReadFile(OutputFilename); 

    //gen key, extract IV from EncData and pass it to decodeData
    key0 = gen_key(pwd, "confidentiality");
    key1 = gen_key(pwd, "integrity");
    memcpy(iv, EncData->Data, IV_LEN);

    ClearData = DecodeData(EncData, key0, key1, 256, iv);

    WriteFile(ClearData, InputFilename);
    //0 and release all data
    memset(ClearData, 0, sizeof(*ClearData));
    memset(EncData, 0, sizeof(*EncData));
    memset(key0, 0, sizeof(*key0));
    memset(key1, 0, sizeof(*key1));
    free(ClearData);
    free(EncData);
    free(key0);
    free(key1);    
}



int main() {

    char    *InputFilename = "test.txt";
    char    *pwd = "rv12345";
       
    EncodeFile(InputFilename, pwd);
    DecodeFile(InputFilename, pwd);

     
    return 0;
}