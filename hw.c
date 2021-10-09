#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"

#define MAX_FILE_SIZE     4096        // for simplification
#define ENCRYPTED_FILE_SUFFIX   ".enc"
#define END_BYTE   0x10
#define PAD_BYTE    0x00
#define AES_BLOCK_SIZE 16
#define IV_LEN 16
//#define PATH_MAX                 256        // for simplification

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


F_DATA *ReadFile(char *InputFilename){
    FILE            *File;         
    int             BytesRead;         
    unsigned char   FileBuf[MAX_FILE_SIZE]; 
    F_DATA          *FileData;          
    
    if ((File = fopen(InputFilename, "rb")) == NULL)
    {
        printf("Error: could not open %s\n", InputFilename);
        perror("fopen");
        exit(1);
    }
    BytesRead = fread(FileBuf, 1, MAX_FILE_SIZE, File);
    
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
    BYTE        *new_data, *enc_buf, *whole, *M; 
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

    //generate HMAC and append to message
    M = HMAC(key1, whole, nl + IV_LEN);
    enc_buf = (BYTE *) malloc (nl + IV_LEN + SHA256_BLOCK_SIZE);
    memcpy(enc_buf, whole, nl + IV_LEN);
    memcpy(enc_buf + nl + IV_LEN, M, SHA256_BLOCK_SIZE);
    //0 and release whole and M
    memset(whole, 0, sizeof(*whole));
    memset(M, 0, sizeof(*M));
    free(whole);  
    free(M);

    //generate struct to return
    EncryptedData = malloc(sizeof(F_DATA));
    EncryptedData->Data = (char *) malloc (nl + IV_LEN + SHA256_BLOCK_SIZE);  //consider IV lenght  and HMAC
    EncryptedData->Length = nl + IV_LEN + SHA256_BLOCK_SIZE; //consider IV lenght and HMAC
    memcpy(EncryptedData->Data, enc_buf, nl + IV_LEN + SHA256_BLOCK_SIZE);
    //0 and release enc_buf
    memset(enc_buf, 0, sizeof(*enc_buf)); 
    free(enc_buf);  
    

    return EncryptedData;
}


F_DATA *DecodeData(F_DATA *DataToDecode, BYTE *key0, BYTE *key1, int keysize, BYTE iv[]){
    BYTE        buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
    F_DATA      *ClearData;  
    WORD        key_schedule[60];
    BYTE        *enc_buf, *orig_message, *M;
    int         blocks, idx, ol, om;
    char        cc;

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

    //malloc memory to store decoded 
    enc_buf = (BYTE *) malloc (om);
    ol = om;

    //decrypt message in DataToDecode->Data, decoded moves to enc_buf
    aes_key_setup(key0, key_schedule, keysize);
    blocks = om / AES_BLOCK_SIZE;
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
