#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_lib/aes.c"

#define MAX_FILE_SIZE     4096        // for simplification
#define ENCRYPTED_FILE_SUFFIX   ".enc"
#define END_BYTE   0x10
#define PAD_BYTE    0x00
#define AES_BLOCK_SIZE 16
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

void xor(const BYTE in[], BYTE out[], size_t len)
{
	size_t idx;

	for (idx = 0; idx < len; idx++)
		out[idx] ^= in[idx];
}


F_DATA EncodeData(F_DATA DataToEncode, BYTE key[], int keysize, BYTE iv[]){
    BYTE        buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
    F_DATA      EncryptedData;  
    WORD        key_schedule[60];
    BYTE        *new_data, *enc_buf; 
    int         blocks, idx, nl, ti;

    //length of padded data
    nl = DataToEncode.Length;
    ti = DataToEncode.Length;
    
    nl++;
    while(nl%AES_BLOCK_SIZE){
        nl++;
    }

    //malloc memory to store padded data  
    new_data = (BYTE *) malloc (nl);
    enc_buf = (BYTE *) malloc (nl);
    EncryptedData.Data = (char *) malloc (nl);
    EncryptedData.Length = nl; 

    //copy old data to new data holder
    memcpy(new_data, DataToEncode.Data, DataToEncode.Length);

    //add end byte and padd bytes to new_data
    *(new_data+ti) = END_BYTE;
    ti++;
    while(ti<nl){
        *(new_data+ti) = PAD_BYTE;
        ti++;
    }

    aes_key_setup(key, key_schedule, keysize);

    blocks = EncryptedData.Length / AES_BLOCK_SIZE;
    memcpy(iv_buf, iv, AES_BLOCK_SIZE);

    for (idx = 0; idx < blocks; idx++) {
		memcpy(buf_in, &new_data[idx * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
		xor(iv_buf, buf_in, AES_BLOCK_SIZE);
		aes_encrypt(buf_in, buf_out, key_schedule, keysize);
		memcpy(&enc_buf[idx * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
		memcpy(iv_buf, buf_out, AES_BLOCK_SIZE);
	}
    //aes_encrypt(new_data, enc_buf, key_schedule, keysize);
            
    memcpy(EncryptedData.Data, enc_buf, nl);

    return EncryptedData;
}


F_DATA DecodeData(F_DATA DataToDecode, BYTE key[], int keysize, BYTE iv[]){
    BYTE        buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
    F_DATA      ClearData;  
    WORD        key_schedule[60];
    BYTE        *enc_buf;
    int         blocks, idx, ol;
    char        cc;

    //malloc memory to store decoded 
    enc_buf = (BYTE *) malloc (DataToDecode.Length);
    ol = DataToDecode.Length;

    aes_key_setup(key, key_schedule, keysize);   

    blocks = DataToDecode.Length / AES_BLOCK_SIZE;
    memcpy(iv_buf, iv, AES_BLOCK_SIZE);

	for (idx = 0; idx < blocks; idx++) {
		memcpy(buf_in, &DataToDecode.Data[idx * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
		aes_decrypt(buf_in, buf_out, key_schedule, keysize);
		xor(iv_buf, buf_out, AES_BLOCK_SIZE);
		memcpy(&enc_buf[idx * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
		memcpy(iv_buf, buf_in, AES_BLOCK_SIZE);
	}

    //aes_decrypt(DataToDecode.Data, enc_buf, key_schedule, keysize);

    cc = *(enc_buf+ol-1);
    while(cc != END_BYTE){
        ol--;
        cc = *(enc_buf+ol-1);
    }
    ol--;    
    
    ClearData.Data = (char *) malloc (ol);
    ClearData.Length = ol;

    memcpy(ClearData.Data, enc_buf, ol);

    return ClearData;
}


void EncodeFile(char *InputFilename, BYTE key[], BYTE iv[]) {
    F_DATA          ClearData;          
    F_DATA          EncData;          
    char            OutputFilename[PATH_MAX];
    
    ClearData = ReadFile(InputFilename);    

    EncData = EncodeData(ClearData, key, 256, iv);

    strcpy(OutputFilename, InputFilename);
    strcat(OutputFilename, ENCRYPTED_FILE_SUFFIX);

    WriteFile(EncData, OutputFilename);
    
}


void DecodeFile(char *InputFilename, BYTE key[], BYTE iv[]) {
    F_DATA          EncData;          
    F_DATA          ClearData;          
    char            OutputFilename[PATH_MAX];
    int             len;
    
    EncData = ReadFile(InputFilename);    

    ClearData = DecodeData(EncData, key, 256, iv);

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

    BYTE iv[1][16] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	};

    EncodeFile(InputFilename, key[0], iv[0]);
    DecodeFile(EncFilename, key[0], iv[0]);

    return 0;
}
