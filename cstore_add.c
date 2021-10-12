#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.c"

void EncodeFile(char *ArchFilename, char *InputFilename, char *pwd) { 
    F_DATA          *ClearData, *ArchData, *EncData;          
    BYTE iv[IV_LEN] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}; //this should be random (ToDo, use method)
    BYTE            *key0, *key1;    

    //read arch data
    ArchData = ReadFile(ArchFilename);

    
    //generate key and IV here
    key0 = gen_key(pwd, "confidentiality");
    key1 = gen_key(pwd, "integrity");

    //validate HMAC from Arch
    if(ArchData->Length){
        ValidateHMAC(ArchData, key1);
    }

    
    //read clear data and encode it
    ClearData = ReadFile(InputFilename);

    //generate IV
    //iv = 

    //Encode Data (IV + File)
    EncData = EncodeData(ClearData, key0, key1, 256, iv);
    //free clear data
    //free others?

    
    WriteToArchive(EncData, ArchData, InputFilename, ArchFilename, key1);
    //delete InputFileName
    DeleteFile(InputFilename);

}


void DecodeFile(char *ArchFilename, char *InputFilename, char *pwd) {  
    F_DATA          *ClearData, *ArchData, *EncData;          
    char            OutputFilename[PATH_MAX];
    BYTE            iv[IV_LEN];
    BYTE            *key0, *key1;
    int             pos;

    //read arch data
    ArchData = ReadFile(ArchFilename);

     

    //generate key and IV here
    key0 = gen_key(pwd, "confidentiality");
    key1 = gen_key(pwd, "integrity");

    //validate HMAC from Arch
    if(ArchData->Length){
        ValidateHMAC(ArchData, key1);
    }

    

    //obtain position in ArchData
    pos = find_pos(ArchData, InputFilename);
        
    //Read data from archive using the position 
    EncData = ReadFromArchive(ArchData, pos); 

    
    
    //Extract iv
    memcpy(iv, EncData->Data, IV_LEN);

    //Decode data
    ClearData = DecodeData(EncData, key0, key1, 256, iv);

    WriteFile(ClearData, InputFilename);   

}


void DeleteFromFile(char *ArchFilename, char *InputFilename, char *pwd) {     
    //method for deleting file from archive
    F_DATA          *ArchData;
    int beg, end, len;

    //key1 = gen_key(pwd, "integrity");

    //validate HMAC from Arch

    //read arch
    ArchData = ReadFile(ArchFilename);
    beg = find_beg(ArchData, InputFilename);
    end = find_end(ArchData, InputFilename);
    len = ArchData->Length;

    printf("beg is %i\n", beg);
    printf("end is %i\n", end);

    //arch len
    //find beg
    //find end

    //analyze four cases

    //malloc new arch, new length, memcpy respective

    //recompute HMAC

    //write neW archfile wiht new HMAC

    printf("Im not implemented yet\n");
}

void ListFiles(char *ArchFilename) {     
    //method for listing all files in archive ?? pwd

    //clever use of find_end by continously re assigning new name
    //add always termination char for printing

    printf("Im not implemented yet\n");
}


int main() {

    char    *ArchFilename = "archive";
    char    *InputFilename = "test.txt";
    char    *InputFilename1 = "test0.txt";
    char    *pwd = "rv12345";
       
    EncodeFile(ArchFilename, InputFilename, pwd);
    EncodeFile(ArchFilename, InputFilename1, pwd);
    //DeleteFromFile(ArchFilename, InputFilename1, pwd);
    DecodeFile(ArchFilename, InputFilename1, pwd);
    DecodeFile(ArchFilename, InputFilename, pwd);
    
     
    return 0;
}