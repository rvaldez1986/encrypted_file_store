#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.c"

void EncodeFile(char *ArchFilename, char *InputFilename, char *pwd) { 
    F_DATA          *ClearData, *ArchData, *EncData;          
    BYTE iv[IV_LEN] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}; //this should be random (ToDo)
    BYTE            *key0, *key1;
    int check;

    //read arch data
    ArchData = ReadFile(ArchFilename);

    if(ArchData->Length){
        memcpy(&check, &ArchData->Data[SHA256_BLOCK_SIZE + 12], 4);
        printf("read from EncodeFile is: %i\n", check);
    }    

    //generate key and IV here
    key0 = gen_key(pwd, "confidentiality");
    key1 = gen_key(pwd, "integrity");

    //validate HMAC from Arch

    
    //read clear data and encode it
    ClearData = ReadFile(InputFilename);

    //Encode Data (IV + File)
    EncData = EncodeData(ClearData, key0, key1, 256, iv);
    //free clear data
    //free others?

    if(ArchData->Length){
        memcpy(&check, &ArchData->Data[SHA256_BLOCK_SIZE + 12], 4);
        printf("passing to WriteToArchive is: %i\n", check);
    }

    WriteToArchive(EncData, ArchData, InputFilename, ArchFilename, key1);
    //delete InputFileName
    DeleteFile(InputFilename);

}


void DecodeFile(char *ArchFilename, char *InputFilename, char *pwd) {  
    F_DATA          *ClearData, *ArchData, *EncData;          
    char            OutputFilename[PATH_MAX];
    BYTE            iv[IV_LEN];
    BYTE            *key0, *key1;
    int             pos, check;

    //read arch data
    ArchData = ReadFile(ArchFilename);

     if(ArchData->Length){
        memcpy(&check, &ArchData->Data[SHA256_BLOCK_SIZE + 12], 4);
        printf("read from DecodeFile is: %i\n", check);
    }

    //generate key and IV here
    key0 = gen_key(pwd, "confidentiality");
    key1 = gen_key(pwd, "integrity");

    //validate HMAC from Arch

    

    //obtain position in ArchData
    pos = SHA256_BLOCK_SIZE + 12; //HMAC + 4 for len + 8 for name (test.txt)
    //Read data from archive using the position 
    EncData = ReadFromArchive(ArchData, pos); 

    
    
    //Extract iv
    memcpy(iv, EncData->Data, IV_LEN);

    //Decode data
    ClearData = DecodeData(EncData, key0, key1, 256, iv);

    WriteFile(ClearData, InputFilename); 

    
    
    

}



int main() {

    char    *ArchFilename = "archive";
    char    *InputFilename = "test.txt";
    char    *pwd = "rv12345";
       
    //EncodeFile(ArchFilename, InputFilename, pwd);
    DecodeFile(ArchFilename, InputFilename, pwd);
    

     
    return 0;
}