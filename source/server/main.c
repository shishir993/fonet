/* 
 * File:   main.c
 * Author: shishir
 *
 * Created on April 16, 2013, 5:22 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include "../common/defs.h"
#include "../common/cutils.h"
#include "../common/helpers.h"

BOOL fUnitTests();

/**
 * 
 * @param argc
 * @param argv
 * @return 
 */
int main(int argc, char** argv)
{
    
    if(!fUnitTests())
        return 1;
    
    return (EXIT_SUCCESS);
}


BOOL fUnitTests()
{
    
    fInitGCrypt();
    
    // test sizes
    {
        int in, out, reqsize;

        in = 64;
        out = 64;
        if(fIsBufSizeEnough(in,out,&reqsize))
            printf("Enough: %d %d %d\n", in, out, reqsize);
        else
            printf("NOT Enough: %d %d %d\n", in, out, reqsize);

        in = 20;
        out = 20;
        if(fIsBufSizeEnough(in,out,&reqsize))
            printf("Enough: %d %d %d\n", in, out, reqsize);
        else
            printf("NOT Enough: %d %d %d\n", in, out, reqsize);

        in = 13;
        out = 13;
        if(fIsBufSizeEnough(in,out,&reqsize))
            printf("Enough: %d %d %d\n", in, out, reqsize);
        else
            printf("NOT Enough: %d %d %d\n", in, out, reqsize);

        in = 70;
        out = 70;
        if(fIsBufSizeEnough(in,out,&reqsize))
            printf("Enough: %d %d %d\n", in, out, reqsize);
        else
            printf("NOT Enough: %d %d %d\n", in, out, reqsize);

        in = 4;
        out = 4;
        if(fIsBufSizeEnough(in,out,&reqsize))
            printf("Enough: %d %d %d\n", in, out, reqsize);
        else
            printf("NOT Enough: %d %d %d\n", in, out, reqsize);
    }
    
    // test encryption
    char szMessage[] = "this is plaintext";
    char szKey[MAX_PASSWD+1];
    BYTE abCipher[32];
    
    char abDecrypted[32];
    
    AES_ENCDATA aesData;
    AES_DECDATA aesDecData;
    
    void *pvPadded = NULL;
    int nPaddedSize = 0;
    
    memset(szKey, 0, sizeof(szKey));
    printf("Enter the key: ");
    scanf("%s", szKey);
    
    if(!fConvertStrToKey(szKey, strlen(szKey), aesData.abKey, sizeof(aesData.abKey)))
        return FALSE;
    
    if(!fPadInput(szMessage, strlen(szMessage)+1, &pvPadded, &nPaddedSize, NULL))
        return FALSE;
    
    aesData.pvInputBuf = pvPadded;
    aesData.nInputSize = nPaddedSize;
    aesData.pvOutputBuf = abCipher;
    aesData.nOutputSize = sizeof(abCipher);
    
    if(!fAESEncrypt(&aesData))
        return FALSE;
    
    free(pvPadded);
    pvPadded = NULL;
    
    logdbg("Ciphertext: ");
    vPrintBytes(aesData.pvOutputBuf, aesData.nOutputSize);
    
    // decrypt
    memcpy(aesDecData.abCounter, aesData.abCounter, sizeof(aesData.abCounter));
    memcpy(aesDecData.abKey, aesData.abKey, sizeof(aesData.abKey));
    //aesDecData.nActualPlainTextSize = strlen(szMessage)+1;
    aesDecData.pvInputBuf = aesData.pvOutputBuf;
    aesDecData.nInputSize = sizeof(abCipher);
    aesDecData.pvOutputBuf = abDecrypted;
    aesDecData.nOutputSize = sizeof(abDecrypted);
    if(!fAESDecrypt(&aesDecData))
        return FALSE;
    
    logdbg("Plaintext: ");
    vPrintBytes(abDecrypted, sizeof(abDecrypted));
    printf("%s", abDecrypted);
    
    // check if encrypt and decrypt was fine
    
    return TRUE;
    
}// fUnitTests()
