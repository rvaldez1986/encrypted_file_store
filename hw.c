#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_lib/aes.c"

#define MAX_FILE_SIZE     4096        // for simplification
#define ENCRYPTED_FILE_SUFFIX   ".enc"
//#define PATH_MAX                 256        // for simplification

typedef struct f_data{
    int Length;/* in bytes */
    char *Data;
} F_DATA;

void WriteFile(
    F_DATA DataToWrite,
    char *OutputFilename)
{
    FILE    *OutputFile;
    int     BytesLeft;
    char    *pCurrent;

    if ((OutputFile = fopen(OutputFilename, "wb")) == NULL)
    {
        printf("Error: could not open %s\n", OutputFilename);
        perror("fopen");
        exit(1);
    }
    
    BytesLeft   = DataToWrite.Length;
    pCurrent = DataToWrite.Data;

    if (fwrite(pCurrent, 1, BytesLeft, OutputFile) != BytesLeft) {
        printf("Error writing file\n");
        exit(1);
    }   
    
    fclose(OutputFile);
}


F_DATA ReadFile(char *InputFilename){
    FILE            *File;         
    int             BytesRead;         
    unsigned char   FileBuf[MAX_FILE_SIZE]; 
    F_DATA          FileData;          
    
    if ((File = fopen(InputFilename, "rb")) == NULL)
    {
        printf("Error: could not open %s\n", InputFilename);
        perror("fopen");
        exit(1);
    }
    BytesRead = fread(FileBuf, 1, MAX_FILE_SIZE, File);
    FileData.Length = BytesRead;
    FileData.Data = FileBuf;
    if (BytesRead == 0)
    {
        printf("Error: did not read any bytes from file\n");
        exit(1);
    }
    if (!feof(File))
    {
       printf("Error: exceeded currently supported maximum file size\n");
        exit(1);
    }
    fclose(File);

    return FileData;

}


F_DATA EncodeData(F_DATA DataToEncode, BYTE key[], int keysize){
    //here we encode
    F_DATA      EncryptedData;  
    WORD        key_schedule[60];
    BYTE        *new_data; 
    BYTE        *enc_buf; 
    int         nl;

    //length of padded data
    nl = DataToEncode.Length;
    //nl++;
    while(nl%16){
        nl++;
    }

    //malloc memory to store padded data  
    new_data = (BYTE *) malloc (nl);
    enc_buf = (BYTE *) malloc (nl);
    EncryptedData.Data = (char *) malloc (nl);
    EncryptedData.Length = nl; 

    //copy old data to new data holder
    memcpy(new_data, DataToEncode.Data, DataToEncode.Length);

    aes_key_setup(key, key_schedule, keysize);
    aes_encrypt(new_data, enc_buf, key_schedule, keysize);
            
    memcpy(EncryptedData.Data, enc_buf, nl);

       
    return EncryptedData;
}


F_DATA DecodeData(F_DATA DataToDecode, BYTE key[], int keysize){
    //here we encode
    F_DATA      ClearData;  
    WORD        key_schedule[60];
    BYTE        *enc_buf;

    //Pad data to be a multiple of 16  

    //malloc memory to store  
    enc_buf = (BYTE *) malloc (DataToDecode.Length);
    ClearData.Data = (char *) malloc (DataToDecode.Length);
    ClearData.Length = DataToDecode.Length;    
    
    aes_key_setup(key, key_schedule, keysize);    
    aes_decrypt(DataToDecode.Data, enc_buf, key_schedule, keysize);

    memcpy(ClearData.Data, enc_buf, DataToDecode.Length);
    
    return ClearData;
}


void EncodeFile(char *InputFilename, BYTE key[]) {
    F_DATA          ClearData;          
    F_DATA          EncData;          
    char            OutputFilename[PATH_MAX];
    
    ClearData = ReadFile(InputFilename);    

    EncData = EncodeData(ClearData, key, 256);

    strcpy(OutputFilename, InputFilename);
    strcat(OutputFilename, ENCRYPTED_FILE_SUFFIX);

    WriteFile(EncData, OutputFilename);
    
}


void DecodeFile(char *InputFilename, BYTE key[]) {
    F_DATA          EncData;          
    F_DATA          ClearData;          
    char            OutputFilename[PATH_MAX];
    int             len;
    
    EncData = ReadFile(InputFilename);    

    ClearData = DecodeData(EncData, key, 256);

    strcpy(OutputFilename, InputFilename);
    len = strlen(InputFilename);
    OutputFilename[len-4] = '\0';
   

    WriteFile(ClearData, OutputFilename);
    
}



int main() {

    char    *InputFilename = "test.txt";
    char    *EncFilename = "test.txt.enc";

    BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};

    EncodeFile(InputFilename, key[0]);
    DecodeFile(EncFilename, key[0]);

    return 0;
}
