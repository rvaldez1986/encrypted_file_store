#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cstore_utils.c"

void EncodeFile(char *ArchFilename, char *InputFilename, char *pwd) { 
    F_DATA          *ClearData, *ArchData, *EncData;          
    //BYTE iv[IV_LEN] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}; //this should be random (ToDo, use method)
    BYTE            *key0, *key1, *iv; 
    int             pos;   

    //read arch data
    ArchData = ReadFile(ArchFilename, 1);

    
    //generate key and IV here
    key0 = gen_key(pwd, "confidentiality");
    key1 = gen_key(pwd, "integrity");
    iv = gen_iv();

    //validate HMAC from Arch
    if(ArchData->Length){
        ValidateHMAC(ArchData, key1);
    }

    //Check if filename exists in ArchData (if ArchData->Length)
    if(ArchData->Length){
        pos = find_pos(ArchData, InputFilename);
        if(pos>=0){
            free(ArchData->Data);
            free(ArchData);
            printf("File already exists!\n");
            exit(1);
        }
    }
    
    //read clear data and encode it
    ClearData = ReadFile(InputFilename, 0);

    
    //Encode Data (IV + File)
    //encode data frees ClearData
    EncData = EncodeData(ClearData, key0, key1, 256, iv);   
    
    //WriteToArchive frees EncData and ArchData
    WriteToArchive(EncData, ArchData, InputFilename, ArchFilename, key1);
    //delete InputFileName
    DeleteFile(InputFilename);
    
    free(iv);

}


void DecodeFile(char *ArchFilename, char *InputFilename, char *pwd) {  
    F_DATA          *ClearData, *ArchData, *EncData;          
    char            OutputFilename[PATH_MAX];
    BYTE            iv[IV_LEN];
    BYTE            *key0, *key1;
    int             pos;

    //read arch data
    ArchData = ReadFile(ArchFilename, 0); //if file does not exist return error

     

    //generate key here
    key0 = gen_key(pwd, "confidentiality");
    key1 = gen_key(pwd, "integrity");

    //validate HMAC from Arch
    if(ArchData->Length){
        ValidateHMAC(ArchData, key1);
    }

    

    //obtain position in ArchData
    pos = find_pos(ArchData, InputFilename);

    if(pos<0){
        printf("File Name Not found!\n");
        exit(1);
    }
        
    //Read data from archive using the position 
    //readFromArchive frees ArchData
    EncData = ReadFromArchive(ArchData, pos);     
    
    //Extract iv
    memcpy(iv, EncData->Data, IV_LEN);

    //Decode data
    //Decode data frees EncData
    ClearData = DecodeData(EncData, key0, key1, 256, iv);

    WriteFile(ClearData, InputFilename); 
    //free ClearData (if no errors writeFile does not frees it)
    free(ClearData->Data);
    free(ClearData);
}


int DeleteFromArch(char *ArchFilename, char *InputFilename, char *pwd) {     
    //method for deleting file from archive
    F_DATA          *ArchData, *NewArchData;
    BYTE            *enc_buf, *whole, *key1, *M;
    int             beg, end, len;
    
    key1 = gen_key(pwd, "integrity");

    //read arch
    ArchData = ReadFile(ArchFilename, 0); //if archive doesnt exist return error

    if(ArchData->Length == 0){
        free(ArchData->Data);
        free(ArchData);
        printf("Error: cannot delete from empty archive\n");
        exit(1);
    }

    //validate HMAC from Arch
    ValidateHMAC(ArchData, key1);

    //find arch len, beg, end
    beg = find_beg(ArchData, InputFilename);
    end = find_end(ArchData, InputFilename);
    len = ArchData->Length;

    //printf("beg is %i\n", beg);
    //printf("end is %i\n", end);

    //analyze four cases
    if(beg == SHA256_BLOCK_SIZE && end == len){
        //printf("case 0 delete whole file\n");
        //no malloc or anything just delete archive
        DeleteFile(ArchFilename);
        free(ArchData->Data);
        free(ArchData);        
        return 0;
    }


    //malloc new arch, new length (without HMAC)
    enc_buf = (BYTE *) malloc (len - end + beg - SHA256_BLOCK_SIZE);  
    
    if(beg == SHA256_BLOCK_SIZE){
        //printf("case 1 deletd file at the beginnig, others are left at the end\n"); 
        //memcopy respective
        memcpy(enc_buf, &ArchData->Data[end], len - end + beg - SHA256_BLOCK_SIZE);    

    }else{
        if(end == len){
            //printf("case 2 delete file at the end, others are letf at the beginning\n");
            //memcopy respective
            memcpy(enc_buf, &ArchData->Data[SHA256_BLOCK_SIZE], len - end + beg - SHA256_BLOCK_SIZE);

        }else{
            //printf("case 3 delete file at the middle, others are letf at the beggining and at the end\n");
            //memcopy respective
            memcpy(enc_buf, &ArchData->Data[SHA256_BLOCK_SIZE], beg - SHA256_BLOCK_SIZE);
            memcpy(enc_buf + beg - SHA256_BLOCK_SIZE, &ArchData->Data[end], len - end);
        }        
    }

    //free ArchData
    free(ArchData->Data);
    free(ArchData);
    

    //recompute HMAC and add it to enc buf
    M = HMAC(key1, enc_buf, len - end + beg - SHA256_BLOCK_SIZE);

    //malloc new archfile as whole now including HMAC
    whole = (BYTE *) malloc (len - end + beg);  
    //copy HMAC to  whole
    memcpy(whole, M, SHA256_BLOCK_SIZE);     
    //copy whole to whole
    memcpy(whole+SHA256_BLOCK_SIZE, enc_buf, len - end + beg - SHA256_BLOCK_SIZE);     
    //release enc buf
    free(enc_buf);   
    free(M); 

    //malloc neW archfile wiht new HMAC
    NewArchData = malloc(sizeof(F_DATA));
    NewArchData->Data = (char *) malloc (len - end + beg);  
    NewArchData->Length = len - end + beg; 
    memcpy(NewArchData->Data, whole, len - end + beg);
    free(whole);
    
    //delete old arch write New arch file
    DeleteFile(ArchFilename);    
    WriteFile(NewArchData, ArchFilename);    

    //free NewArchData, if WriteFile works it is not freed
    free(NewArchData->Data);
    free(NewArchData);
    return 0;
}

int ListFiles(char *ArchFilename) {     
    //method for listing all files in archive ?? pwd

    //clever use of find_end by continously re assigning new name
    //add always termination char for printing
    F_DATA          *ArchData;
    FILE            *File;
    char            *place_holder;
    int             beg, len, ind, ph;

    ArchData = ReadFile(ArchFilename, 1); //if archive doesnt exist read it anyways ?

    if ((File = fopen("list.txt", "w")) == NULL){
       
        //free ArchData
        free(ArchData->Data);
        free(ArchData);       
        printf("Error! opening file");
        exit(1);

    }

    if(ArchData->Length == 0){

        free(ArchData->Data);
        free(ArchData); 
        fclose(File);
        fwrite("File empty", sizeof(char), 10, File);
        printf("File empty\n"); 
        return 0;       
    }

    beg = SHA256_BLOCK_SIZE; //begin after HMAC
    len = ArchData->Length;
    ind = 1;

    
    while(ind){

        memcpy(&ph, &ArchData->Data[beg], 4);
        if(ph < 0 || ph >= len){

            free(ArchData->Data);
            free(ArchData); 
            fclose(File);
            printf("Error: the archive has some error\n");
            exit(1);
        }

        place_holder = (char *) malloc (ph+1);
        memcpy(place_holder, &ArchData->Data[beg+4], ph);
        *(place_holder+ph) = '\0';
        printf("found %s\n", place_holder);
        *(place_holder+ph) = '\n';
        fwrite(place_holder, sizeof(char), ph+1, File);

        beg = find_end(ArchData, place_holder);

        //printf("new beg value is %i\n", beg);
        
        if(beg>=len)
            ind = 0;        

        free(place_holder);
    }

    //free stuff and close file
    free(ArchData->Data);
    free(ArchData); 
    fclose(File);

    return 0;
    
}


