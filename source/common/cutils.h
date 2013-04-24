#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <gcrypt.h>
#include <gpg-error.h>


#include "defs.h"
#include "sdbg.h"
#include "assert.h"

/* defines */
// algorithms used
#define CRYPT_ALG_CIPHER        GCRY_CIPHER_AES256
#define CRYPT_ALG_HASH          GCRY_MD_SHA256
#define CRYPT_CIPHER_MODE       GCRY_CIPHER_MODE_CTR

// sizes
#define CRYPT_HASH_SIZE_BYTES   32  // SHA256 outputs a 256bit(32byte) hash value
#define CRYPT_BLK_SIZE_BYTES    16  // AES has a 128bit(16byte) block size
#define CRYPT_KEY_SIZE_BYTES    32  // AES256 has a 256bit(32byte) key size
#define CRYPT_CTR_SIZE_BYTES    16  // CTR mode counter value = AES block size

// MACROS
#define fCompareDigests(l,sl,r,rs) ( fCompareBytes(l,sl,r,rs) )

/* end defines */

/* structures */
typedef struct _tagAESEncData {
    BYTE abKey[CRYPT_KEY_SIZE_BYTES];
    
    // input
    void *pvInputBuf;
    int nInputSize;
    
    // output
    BYTE abCounter[CRYPT_BLK_SIZE_BYTES];
    void *pvOutputBuf;
    int nOutputSize;
    
    int err;
    
}AES_ENCDATA;


typedef struct _tagAESDecData {
    // inupt
    BYTE abKey[CRYPT_KEY_SIZE_BYTES];
    BYTE abCounter[CRYPT_BLK_SIZE_BYTES];
    void *pvInputBuf;
    int nInputSize;
    
    // output
    void *pvOutputBuf;
    int nOutputSize;
    
    int err;
    
}AES_DECDATA;

/* end structures */

BOOL fInitGCrypt();

BOOL fGetHash(const void *pvInputData, int nInputSize, BYTE *pbOutBuf, int nOutBufSize, int *pierr);

BOOL fCompareBytes(const void *pvLeft, int nLeftSize, const void *pvRight, int nRightSize);
void vPrintBytes(const void *pvData, int nSize);

BOOL fConvertStrToKey(const char *pszStr, int nLen, BYTE *pbKeyOut, int nSizeOut);
BOOL fIsBufSizeEnough(int inputSize, int outputSize, int *piReqSize);
int  iRoundToBlockSize(int inputSize);
BOOL fPadInput(void *pvInput, int nInSize,
               void **ppvPaddedBuf, int *pnPaddedBufSize,
               int *pierr);
BOOL fSecureAlloc(int sizeBytes, void **pvAllocated);

// SHA256 functions
BOOL fGetHMAC(const BYTE *pbKey, int nKeySize,
        const void *pvInputData, int nInputSize, 
        BYTE *pbOutBuf, int nOutBufSize, int *pierr);
BOOL fGetHash(const void *pvInputData, int nInputSize, 
        BYTE *pbOutBuf, int nOutBufSize, int *pierr);
static BOOL fSHA256Worker(BOOL fHMACEnable, const BYTE *pbKey,
        const void *pvInputData, int nInputSize, BYTE *pbOutBuf, int *pierr);

// AES functions
BOOL fAESEncrypt(AES_ENCDATA *pAESData);
BOOL fAESDecrypt(AES_DECDATA *pAESData);

#endif // _UTILS_H
