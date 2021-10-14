#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"

#define MAX_FILE_SIZE     400096        // max, setup to avoid memory problems
#define END_BYTE   0x10
#define PAD_BYTE    0x00
#define AES_BLOCK_SIZE 16
#define IV_LEN 16
#define PATH_MAX                 256        // for simplification




typedef struct f_data{
    int Length;/* in bytes */
    char *Data;
} F_DATA;


void write_error(char *ErrorText, int len){

    FILE            *File;

    if ((File = fopen("error.txt", "w")) == NULL){
       
        perror("fopen");
        exit(1);

    }

    fwrite(ErrorText, sizeof(char), len, File);
    fclose(File);

}



void WriteFile(
    F_DATA *DataToWrite,
    char *OutputFilename)
{
    FILE    *OutputFile;
    int     BytesLeft;
    char    *pCurrent;

    if ((OutputFile = fopen(OutputFilename, "wb")) == NULL)
    {
        
        free(DataToWrite->Data);
        free(DataToWrite);        
        printf("Error: could not open %s\n", OutputFilename);
        exit(1);
    }
    
    BytesLeft   = DataToWrite->Length;
    pCurrent = DataToWrite->Data;

    if (fwrite(pCurrent, 1, BytesLeft, OutputFile) != BytesLeft) {
        
        free(DataToWrite->Data);
        free(DataToWrite); 
        fclose(OutputFile);
        printf("Error writing file\n");
        exit(1);
    }   
    
    fclose(OutputFile);
}


void DeleteFile(char *Filename)
{
    if (remove(Filename)){   
        printf("Unable to delete the file\n");
        exit(1);
    }
}  



F_DATA *ReadFile(char *InputFilename, int ind){  
    FILE            *File;         
    int             BytesRead;         
    char            *FileBuf; 
    F_DATA          *FileData;  

    FileBuf =  (char *) malloc (MAX_FILE_SIZE);    
    
    if ((File = fopen(InputFilename, "rb")) == NULL)
    {
        if(ind){

            //Create empty file
            File = fopen(InputFilename, "wb");

        }else{

            free(FileBuf);
            printf("Error: could not open or File does not exist %s\n", InputFilename);
            perror("fopen");
            exit(1);
        }
    }
    BytesRead = fread(FileBuf, 1, MAX_FILE_SIZE, File);    
    
    if (BytesRead > MAX_FILE_SIZE)
    {
        free(FileBuf);
        fclose(File);
        printf("Error: exceeded currently supported maximum file size\n");
        exit(1);
    }

    FileData = malloc(sizeof(F_DATA));
    FileData->Data = (char *) malloc (BytesRead);  
    FileData->Length = BytesRead;
    //FileData->Data = FileBuf;
    memcpy(FileData->Data, FileBuf, BytesRead);
    free(FileBuf);    

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
    //len in the size of m
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

BYTE *gen_iv(){
    //generate IV of size IV_LEN
    BYTE       *iv;
    FILE       *File;
    //malloc size IV_LEN
    //https://stackoverflow.com/questions/2572366/how-to-use-dev-random-or-urandom-in-c
    //BYTE iv[IV_LEN] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

    
    if ((File = fopen("/dev/urandom", "r")) == NULL){

        printf("Error: could not open dev/urandom \n");
        exit(1);
    }

    iv = (BYTE *) malloc (IV_LEN);  
    
    fread(iv, 1, IV_LEN, File);
    fclose(File);

    return iv;

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
    new_data = (BYTE *) malloc (nl);    
   
    //copy old data to new data holder
    memcpy(new_data, DataToEncode->Data, DataToEncode->Length);
    //free DataToEncode
    free(DataToEncode->Data);
    free(DataToEncode);


    //add end byte and padd bytes to new_data
    *(new_data+ti) = END_BYTE;
    ti++;
    while(ti<nl){
        *(new_data+ti) = PAD_BYTE;
        ti++;
    } 

    //malloc for holding enc_buf
    enc_buf = (BYTE *) malloc (nl);    

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

    //HMAC validated
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

    //free DataToDecode
    free(DataToDecode->Data);
    free(DataToDecode);

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


void ValidateHMAC(F_DATA *Data, BYTE *key1){
    //check HMAC
    int         om;
    BYTE        *orig_message, *M;
    
    om = Data->Length-SHA256_BLOCK_SIZE;
    if(om <= 0 || om >= Data->Length){   

        free(Data->Data);
        free(Data);
        printf("either data has been tampered or password is incorrect\nCannot validate HMAC from file\n");
        write_error("either data has been tampered or password is incorrect\nCannot validate HMAC from file\n", 86);
        exit(1);

    }

    orig_message = (char *) malloc (om);
    memcpy(orig_message, &Data->Data[SHA256_BLOCK_SIZE], om); 
    M = HMAC(key1, orig_message, om);
    if(memcmp(M, Data->Data, SHA256_BLOCK_SIZE)){   

        free(Data->Data);
        free(Data);
        free(M);
        printf("either data has been tampered or password is incorrect\nCannot validate HMAC from file\n");
        write_error("either data has been tampered or password is incorrect\nCannot validate HMAC from file\n", 86);
        exit(1);

    }
    //0 and release orig_message
    memset(orig_message, 0, sizeof(*orig_message)); 
    free(orig_message);
    free(M);

}






void WriteToArchive(
                    F_DATA *EncData, 
                    F_DATA *ArchData, 
                    char *InputFilename, 
                    char *ArchFilename,
                    BYTE *key1){

    F_DATA          *NewArchData; 
    BYTE            *enc_buf, *whole, *M;   
    int             len;

    
    //HMAC was already validated, ArchData has length 0 if empty
    //malloc memory to store encoded data
    //enc_buf = size EncData + Filename size + 8 (for 2 ints)
    len = strlen(InputFilename);
    enc_buf = (BYTE *) malloc (EncData->Length + len + 8);  

    //printf("orig data size is %i\n", EncData->Length);
    //printf("enc_buf size is %i\n", EncData->Length + len + 8);
    
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
        memcpy(whole, &ArchData->Data[SHA256_BLOCK_SIZE], ArchData->Length - SHA256_BLOCK_SIZE);
        memcpy(whole + ArchData->Length - SHA256_BLOCK_SIZE, enc_buf, EncData->Length + len + 8);
        len = EncData->Length + len + 8 + ArchData->Length - SHA256_BLOCK_SIZE;
        //printf("whole size is %i\n", len);
    }else{
        whole = (BYTE *) malloc (EncData->Length + len + 8);
        memcpy(whole, enc_buf, EncData->Length + len + 8);
        len = EncData->Length + len + 8;
        //printf("whole size is %i\n", len);
    }
    
    
    //release enc_buf, ArchData and EncData (all is on whole now)
    free(enc_buf);
    free(ArchData->Data);
    free(ArchData);
    free(EncData->Data);
    free(EncData);

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

    //printf("archData size is %i\n", len+SHA256_BLOCK_SIZE);    
    //write Archive file with new info
    DeleteFile(ArchFilename);
    WriteFile(NewArchData, ArchFilename);

    //free stuff
    free(NewArchData->Data);
    free(NewArchData);

}


F_DATA *ReadFromArchive(F_DATA *ArchData, int pos){
    F_DATA          *EncData; 
    int             len;

    //HMAC was already validated    
    
    //extract file length
    memcpy(&len, &ArchData->Data[pos], 4);      
        
    //malloc file length for F_DATA
    EncData = malloc(sizeof(F_DATA));
    EncData->Data = (char *) malloc (len);  
    EncData->Length = len;
    
    //Copy to data
    memcpy(EncData->Data, &ArchData->Data[pos+4], len);   

    //free stuff
    free(ArchData->Data);
    free(ArchData);
        
    return EncData;

}


int find_pos(F_DATA *ArchData, char *InputFilename){
    //find position of file in archive
    int len, beg, ph, ind, ret;
    char *place_holder;

    len = ArchData->Length;
    beg = SHA256_BLOCK_SIZE; //begin after HMAC
    ind = 1;
    ret = -1;

    //printf("len is %i\n", len);

    while(ind){

        //printf("beg starts in %i\n", beg);
        if(beg+4 >= len){

            free(ArchData->Data);
            free(ArchData);
            printf("Error: the archive has some error, data could be tampered\n");
            exit(1);
            
        }
        
        memcpy(&ph, &ArchData->Data[beg], 4);
        if(ph < 0 || beg + 4 + ph > len){

            free(ArchData->Data);
            free(ArchData);
            printf("Error: the archive has some error, data could be tampered\n");
            exit(1);

        }

        //printf("size found is %i\n", ph);
        place_holder = (char *) malloc (ph);
        memcpy(place_holder, &ArchData->Data[beg+4], ph);
        //printf("memcmp gives us %i\n", memcmp(place_holder, InputFilename, ph));       
            

        if(memcmp(place_holder, InputFilename, ph)==0){
            ret = beg+4+ph;
            ind = 0;  
            free(place_holder);

        }else{
            beg = beg+4+ph;
            memcpy(&ph, &ArchData->Data[beg], 4);
            beg += (ph+4);

            if(beg>=len)
                ind = 0;
            free(place_holder); 
        }
        
        //printf("beg ends in %i\n", beg);
               

    }
    
    //printf("ret is %i\n", ret);
    
    return ret;
}


int find_beg(F_DATA *ArchData, char *InputFilename){

    //find where data for InputFilename begins
    //we can cleverly use find_pos and delete InputFilename size and 8
    int pos, len;

    pos = find_pos(ArchData, InputFilename);

    if(pos<0){
        free(ArchData->Data);
        free(ArchData);
        printf("File Name Not found!\n");
        exit(1);
    }
    //printf("pos is %i\n", pos);
    len = strlen(InputFilename);

    return pos - len - 4;

}

int find_end(F_DATA *ArchData, char *InputFilename){

    //find where data for InputFilename ends
    //we can cleverly use find_pos, get file size substracting 4 and adding it to find_pos
    int pos, ph;

    pos = find_pos(ArchData, InputFilename);

    if(pos<0){
        free(ArchData->Data);
        free(ArchData);
        printf("File Name Not found!\n");
        exit(1);
    }
    //printf("pos is %i\n", pos);
    
    memcpy(&ph, &ArchData->Data[pos], 4);

    return pos + ph + 4; 


}






