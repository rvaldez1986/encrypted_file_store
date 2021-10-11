#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"

#define MAX_FILE_SIZE     400096        // max setup
#define ENCRYPTED_FILE_SUFFIX   ".enc"
#define END_BYTE   0x10
#define PAD_BYTE    0x00
#define AES_BLOCK_SIZE 16
#define IV_LEN 16
//#define PATH_MAX                 256        // for simplification


//Need to work on api
/**

//check HMAC
    om = DataToDecode->Length-SHA256_BLOCK_SIZE;
    orig_message = (char *) malloc (om);
    memcpy(orig_message, DataToDecode->Data, om); 
    M = HMAC(key1, orig_message, om);
    if(memcmp(M, &DataToDecode->Data[om], SHA256_BLOCK_SIZE)){   

        printf("either data has been tampered or password is incorrect\nCannot extract file");
        exit(1);
    }
    //0 and release orig_message
    memset(orig_message, 0, sizeof(*orig_message)); 
    free(orig_message);

**/



typedef struct f_data{
    int Length;/* in bytes */
    char *Data;
} F_DATA;

void WriteFile(
    F_DATA *DataToWrite,
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
    
    BytesLeft   = DataToWrite->Length;
    pCurrent = DataToWrite->Data;

    if (fwrite(pCurrent, 1, BytesLeft, OutputFile) != BytesLeft) {
        printf("Error writing file\n");
        exit(1);
    }   
    
    fclose(OutputFile);
}

void DeleteFile(char *Filename)
{
   if (remove(Filename))   
      printf("Unable to delete the file\n");
}  



F_DATA *ReadFile(char *InputFilename){
    FILE            *File;         
    int             BytesRead;         
    char            *FileBuf; 
    F_DATA          *FileData;  

    FileBuf =  (char *) malloc (MAX_FILE_SIZE);    
    
    if ((File = fopen(InputFilename, "rb")) == NULL)
    {
        printf("Error: could not open %s\n", InputFilename);
        perror("fopen");
        exit(1);
    }
    BytesRead = fread(FileBuf, 1, MAX_FILE_SIZE, File);
    
    
    if (!feof(File))
    {
       printf("Error: exceeded currently supported maximum file size\n");
        exit(1);
    }

    FileData = malloc(sizeof(F_DATA));
    FileData->Data = (char *) malloc (BytesRead);  
    FileData->Length = BytesRead;
    FileData->Data = FileBuf;

    fclose(File);

    return FileData;

}

void xor(const BYTE *in, BYTE *out, size_t len)
{
	size_t idx;

	for (idx = 0; idx < len; idx++)
		out[idx] ^= in[idx];
}

BYTE *HMAC(BYTE *key, BYTE *m, size_t len){
    //H(K or opad || H((K or ipad)||m))
    BYTE        *buf0, *buf1, *buf2;
    SHA256_CTX      ctx;

    BYTE opad[SHA256_BLOCK_SIZE] = {0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	                                 0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c};
    BYTE ipad[SHA256_BLOCK_SIZE] = {0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	                                 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36};
    
    buf0 = (BYTE *) malloc(SHA256_BLOCK_SIZE);
    buf1 = (BYTE *) malloc(len+SHA256_BLOCK_SIZE);

    //K or ipad
    memcpy(buf0, key, SHA256_BLOCK_SIZE);
    xor(ipad, buf0, SHA256_BLOCK_SIZE);
    //|| m
    memcpy(buf1, buf0, SHA256_BLOCK_SIZE);
    memcpy(buf1+SHA256_BLOCK_SIZE, m, len);
    // H((K or ipad)||m)
    sha256_init(&ctx);
	sha256_update(&ctx, buf1, len+SHA256_BLOCK_SIZE);
	sha256_final(&ctx, buf0);
    free(buf1);

    //K or opad
    buf2 = (BYTE *) malloc(SHA256_BLOCK_SIZE);
    memcpy(buf2, key, SHA256_BLOCK_SIZE);
    xor(opad, buf2, SHA256_BLOCK_SIZE);
    //K or opad || H((K or ipad)||m)
    buf1 = (BYTE *) malloc(2*SHA256_BLOCK_SIZE);
    memcpy(buf1, buf2, SHA256_BLOCK_SIZE);
    memcpy(buf1+SHA256_BLOCK_SIZE, buf0, SHA256_BLOCK_SIZE);
    free(buf0);
    free(buf2);

    //H(K or opad || H((K or ipad)||m))
    buf0 = (BYTE *) malloc(SHA256_BLOCK_SIZE);
    sha256_init(&ctx);
	sha256_update(&ctx, buf1, 2*SHA256_BLOCK_SIZE);
	sha256_final(&ctx, buf0);
    free(buf1);

    return buf0;

} 


F_DATA *EncodeData(F_DATA *DataToEncode, BYTE *key0, BYTE *key1, int keysize, BYTE iv[]){
    BYTE        buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
    F_DATA      *EncryptedData;  
    WORD        key_schedule[60];
    BYTE        *new_data, *enc_buf, *whole; 
    int         blocks, idx, nl, ti;

    //length of padded data
    nl = DataToEncode->Length;
    ti = DataToEncode->Length;    
    nl++;
    while(nl%AES_BLOCK_SIZE){
        nl++;
    }
    
    //malloc memory to store padded data
    enc_buf = (BYTE *) malloc (nl);
    new_data = (BYTE *) malloc (nl);    
   
    //copy old data to new data holder
    memcpy(new_data, DataToEncode->Data, DataToEncode->Length);
    //add end byte and padd bytes to new_data
    *(new_data+ti) = END_BYTE;
    ti++;
    while(ti<nl){
        *(new_data+ti) = PAD_BYTE;
        ti++;
    }     

    //encrypt data
    aes_key_setup(key0, key_schedule, keysize);
    blocks = nl / AES_BLOCK_SIZE;
    memcpy(iv_buf, iv, AES_BLOCK_SIZE);   
    for (idx = 0; idx < blocks; idx++) {
	    memcpy(buf_in, &new_data[idx * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
		xor(iv_buf, buf_in, AES_BLOCK_SIZE);
		aes_encrypt(buf_in, buf_out, key_schedule, keysize);
		memcpy(&enc_buf[idx * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
		memcpy(iv_buf, buf_out, AES_BLOCK_SIZE);
	}    

    //0 and release new data
    memset(new_data, 0, sizeof(*new_data));
    free(new_data);
    //join encrypted + iv
    whole = (BYTE *) malloc (nl+IV_LEN);                 
    memcpy(whole, iv, IV_LEN); //Include IV
    memcpy(whole+IV_LEN, enc_buf, nl);
    //0 and release enc_buf
    memset(enc_buf, 0, sizeof(*enc_buf));
    free(enc_buf);    

    //generate struct to return
    EncryptedData = malloc(sizeof(F_DATA));
    EncryptedData->Data = (char *) malloc (nl + IV_LEN);  //consider IV lenght 
    EncryptedData->Length = nl + IV_LEN; //consider IV lenght
    memcpy(EncryptedData->Data, whole, nl + IV_LEN);
    //0 and release enc_buf
    memset(whole, 0, sizeof(*whole)); 
    free(whole);    

    return EncryptedData;
}


F_DATA *DecodeData(F_DATA *DataToDecode, BYTE *key0, BYTE *key1, int keysize, BYTE iv[]){
    BYTE        buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
    F_DATA      *ClearData;  
    WORD        key_schedule[60];
    BYTE        *enc_buf;
    int         blocks, idx, ol;
    char        cc;

    //check HMAC
    ol = DataToDecode->Length;
    
    //malloc memory to store decoded 
    enc_buf = (BYTE *) malloc (ol);
    
    //decrypt message in DataToDecode->Data, decoded moves to enc_buf
    aes_key_setup(key0, key_schedule, keysize);
    blocks = ol / AES_BLOCK_SIZE;
    memcpy(iv_buf, iv, AES_BLOCK_SIZE);
	for (idx = 0; idx < blocks; idx++) {
		memcpy(buf_in, &DataToDecode->Data[idx * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
		aes_decrypt(buf_in, buf_out, key_schedule, keysize);
		xor(iv_buf, buf_out, AES_BLOCK_SIZE);
		memcpy(&enc_buf[idx * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
		memcpy(iv_buf, buf_in, AES_BLOCK_SIZE);
	}

    //obtain original length of message
    cc = *(enc_buf+ol-1);
    while(cc != END_BYTE){
        ol--;
        cc = *(enc_buf+ol-1);
    }
    ol--;    
    
    //malloc structure to retun the decrypted message
    ClearData = malloc(sizeof(F_DATA));
    ClearData->Data = (char *) malloc (ol-IV_LEN);  //extract iv length
    ClearData->Length = ol-IV_LEN; //extract iv length
    memcpy(ClearData->Data, enc_buf+IV_LEN, ol-IV_LEN); //extract iv length (enc_buf+ivlength)
    //0 and release enc_buf
    memset(enc_buf, 0, sizeof(*enc_buf)); 
    free(enc_buf);     

    return ClearData;
}

BYTE *gen_key(char *pwd, char *type){
    //generate key from password, use it for confidentiality or integrity (type)
    BYTE            *buf;
    SHA256_CTX      ctx;
	int             idx;
    char            *p_text;

    buf = malloc(SHA256_BLOCK_SIZE);
    p_text = malloc(strlen(pwd)+strlen(type));
    memcpy(p_text, pwd, strlen(pwd));
    memcpy(p_text+strlen(pwd), type, strlen(type));

    sha256_init(&ctx);
	for (idx = 0; idx < 10000; ++idx)
	    sha256_update(&ctx, p_text, strlen(pwd)+strlen(type));
	sha256_final(&ctx, buf);
    //0 and release p_text
    memset(p_text, 0, sizeof(*p_text));
    free(p_text);

    return buf;
}



void WriteToArchive(
                    F_DATA *EncData, 
                    F_DATA *ArchData, 
                    char *InputFilename, 
                    char *ArchFilename,
                    BYTE *key1){

    F_DATA          *NewArchData; 
    BYTE            *enc_buf, *whole, *M;   
    int             len, check;

    if(ArchData->Length){
        memcpy(&check, &ArchData->Data[SHA256_BLOCK_SIZE + 12], 4);
        printf("read in  WriteToArchive is: %i\n", check);
    }

    //HMAC was already validated, ArchData has length 0 if empty
    //malloc memory to store encoded data
    //enc_buf = size EncData + Filename size + 8 (for 2 ints)
    len = strlen(InputFilename);
    enc_buf = (BYTE *) malloc (EncData->Length + len + 8);     
    
    //copy to enc_buf |name length|name|file length|file     
    memcpy(enc_buf, &len, 4);
    memcpy(enc_buf+4, InputFilename, len);
    memcpy(enc_buf+4+len, &EncData->Length, 4);       
    memcpy(enc_buf+4+len+4, EncData->Data, EncData->Length);    

    //whole = malloc size enc_buf + (size of ArchData - HMAC_SIZE if ArchData is not empty)
    //copy ArchData (without HMAC) to whole (if ArchData is not empty)
    //copy enc_buf to whole next to it
    if(ArchData->Length){
        whole = (BYTE *) malloc (EncData->Length + len + 8 + ArchData->Length - SHA256_BLOCK_SIZE);
        
        memcpy(&check, &ArchData->Data[SHA256_BLOCK_SIZE + 12], 4);
        printf("check  inside if is: %i\n", check);

        memcpy(whole, &ArchData->Data[SHA256_BLOCK_SIZE], ArchData->Length - SHA256_BLOCK_SIZE);
        memcpy(whole + ArchData->Length - SHA256_BLOCK_SIZE, enc_buf, EncData->Length + len + 8);
        len = EncData->Length + len + 8 + ArchData->Length - SHA256_BLOCK_SIZE;
    }else{
        whole = (BYTE *) malloc (EncData->Length + len + 8);
        memcpy(whole, enc_buf, EncData->Length + len + 8);
        len = EncData->Length + len + 8;
    }
    
    
    //release enc_buf
    free(enc_buf);
    free(ArchData->Data);
    free(ArchData);

    //calculate HMAC of whole 
    M = HMAC(key1, whole, len);

    //enc_buf = malloc size of whole + HMAC
    enc_buf = (BYTE *) malloc (len+SHA256_BLOCK_SIZE); 
    //copy HMAC to  enc_buf
    memcpy(enc_buf, M, SHA256_BLOCK_SIZE);     
    //copy whole to enc_buf
    memcpy(enc_buf+SHA256_BLOCK_SIZE, whole, len);     
    //release whole
    free(whole);

    //malloc F_DATA structure to write to Archive
    //store enc_buf and enc_buf length 
    NewArchData = malloc(sizeof(F_DATA));
    NewArchData->Data = (char *) malloc (len+SHA256_BLOCK_SIZE);  
    NewArchData->Length = len+SHA256_BLOCK_SIZE; 
    memcpy(NewArchData->Data, enc_buf, len+SHA256_BLOCK_SIZE); 
    free(enc_buf);

    memcpy(&check, &NewArchData->Data[SHA256_BLOCK_SIZE + 12], 4);
    printf("check when we save is: %i\n", check);

    //write Archive file with new info
    DeleteFile(ArchFilename);
    WriteFile(NewArchData, ArchFilename);

}


F_DATA *ReadFromArchive(F_DATA *ArchData, int pos){
    F_DATA          *EncData; 
    int             len;

    //HMAC was already validated    
    
    //extract file length
    memcpy(&len, &ArchData->Data[pos], 4);

    printf("read bytes %i\n", len);

    
        
    //malloc file length for F_DATA
    EncData = malloc(sizeof(F_DATA));
    EncData->Data = (char *) malloc (len);  
    EncData->Length = len;

    
    //Copy to data
    memcpy(EncData->Data, &ArchData->Data[pos+4], len); 

   
    
        
    return EncData;
    

}


int find_pos(F_DATA *ArchData, char *InputFilename){
    //find position of file in archive
    printf("Im not developed yet");
    return 0;
}




