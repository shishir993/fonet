#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <gcrypt.h>
#include <gpg-error.h>
#include <netinet/in.h>


#include "defs.h"
#include "sdbg.h"
#include "assert.h"

/* defines */
// algorithms used
#define CRYPT_ALG_CIPHER        GCRY_CIPHER_AES256
#define CRYPT_ALG_HASH          GCRY_MD_SHA256
#define CRYPT_ALG_KDF           GCRY_KDF_PBKDF2
#define CRYPT_CIPHER_MODE       GCRY_CIPHER_MODE_CTR

#define CRYPT_KDF_ITRS          10000

// sizes
#define CRYPT_HASH_SIZE_BYTES   32  // SHA256 outputs a 256bit(32byte) hash value
#define CRYPT_BLK_SIZE_BYTES    16  // AES has a 128bit(16byte) block size
#define CRYPT_KEY_SIZE_BYTES    32  // AES256 has a 256bit(32byte) key size
#define CRYPT_CTR_SIZE_BYTES    16  // CTR mode counter value = AES block size
#define CRYPT_SALT_SIZE_BYTES   8   // 64bit salt to store password


// MACROS
#define fCompareDigests(l,sl,r,rs) ( fCompareBytes(l,sl,r,rs) )
#define vSecureFree(pvmem) ( gcry_free(pvmem) )

/* end defines */

/* structures */
typedef struct _tagAESEncData {
    // input
    void *pvInputBuf;
    int nInputSize;
    BYTE *pbKey;
    int nKeySize;
    
    // output
    BYTE abCounter[CRYPT_BLK_SIZE_BYTES];
    void *pvOutputBuf;
    int nOutputSize;
    
    int err;
    
}AES_ENCDATA;


typedef struct _tagAESDecData {
    // inupt
    void *pvInputBuf;
    int nInputSize;
    BYTE *pbKey;
    int nKeySize;
    BYTE abCounter[CRYPT_BLK_SIZE_BYTES];
    
    // output
    void *pvOutputBuf;
    int nOutputSize;
    
    int err;
    
}AES_DECDATA;


typedef struct _userPasswd {
    char szUsername[MAX_USERNAME+1];
	BYTE abSalt[CRYPT_SALT_SIZE_BYTES];
	BYTE abDerivedKey[CRYPT_KEY_SIZE_BYTES];
}USER_PASSWD;


typedef struct _sharedKey {
    char szAlice[INET_ADDRSTRLEN+1];
    char szBob[INET_ADDRSTRLEN+1];
    BYTE abKey[CRYPT_KEY_SIZE_BYTES];
}SHARED_KEY;

/* end structures */

BOOL fInitGCrypt();

BOOL fGetHash(const void *pvInputData, int nInputSize, BYTE *pbOutBuf, int nOutBufSize, int *pierr);

BOOL fCompareBytes(const void *pvLeft, int nLeftSize, const void *pvRight, int nRightSize);
void vPrintBytes(const void *pvData, int nSize);

BOOL fConvertStrToKey(const char *pszStr, int nLen, BYTE *pbKeyOut, int nSizeOut);
BOOL fPassphraseToKey(const char *pszPass, int nPassLen, 
        BYTE *pbSaltOut, int saltOutSize,
        BYTE *pbKeyOut, int keyOutSize);

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
