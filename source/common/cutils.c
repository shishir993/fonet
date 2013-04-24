
#include <unistd.h>

#include "cutils.h"


/**
 * Checks for correct version of Libgrcypt and initializes it. 
 * Also initializes a secure memory area of size 32678 bytes (32kB).
 * @return TRUE/FALSE depending on whether the correct version is installed or not.
 */
BOOL fInitGCrypt()
{
    /*  Version check should be the very first call because it
        makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        logdbg("libgcrypt version mismatch");
        return FALSE;
    }

   /* We don't want to see any warnings, e.g. because we have not yet
      parsed program options which might be used to suppress such
      warnings. */
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
      process might still be running with increased privileges and that
      the secure memory has not been intialized.  */

    /* Allocate a pool of 32k secure memory.  This makes the secure memory
      available and also drops privileges where needed.  */
    gcry_control (GCRYCTL_INIT_SECMEM, 32678, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
      a problem with the secure memory. */
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    loginfo("gcrypt library initialization done...");
    
#ifdef _DEBUG
    printf("Now, some numbers...\n");
    printf("char      : %u byte\n", sizeof(char));
    printf("short     : %u bytes\n", sizeof(short));
    printf("int       : %u bytes\n", sizeof(int));
    printf("long      : %u bytes\n", sizeof(long));
    printf("float     : %u bytes\n", sizeof(float));
    printf("double    : %u bytes\n", sizeof(double));
    printf("ldouble   : %u bytes\n", sizeof(long double));
    printf("%s\n::block len: %u\n::key len: %u\n", gcry_cipher_algo_name(CRYPT_ALG_CIPHER), 
            gcry_cipher_get_algo_blklen(CRYPT_ALG_CIPHER), 
            gcry_cipher_get_algo_keylen(CRYPT_ALG_CIPHER));
    
    printf("%s\n::digest len: %u\n", gcry_md_algo_name(CRYPT_ALG_HASH), 
            gcry_md_get_algo_dlen(CRYPT_ALG_HASH));
#endif // _DEBUG

    return TRUE;

}// fInitGCrypt()


/**
 * Compares the left and right data byte-wise
 * @param pvLeft 
 * @param nLeftSize 
 * @param pvRight 
 * @param nRightSize 
 * @return TRUE/FALSE depending on whether the two data are equal or not
 */
BOOL fCompareBytes(const void *pvLeft, int nLeftSize, const void *pvRight, int nRightSize)
{
    ASSERT(pvLeft && pvRight);
    ASSERT(nLeftSize > 0 && nRightSize > 0);
    
    int i;
    const BYTE *pbl = (BYTE*)pvLeft;
    const BYTE *pbr = (BYTE*)pvRight;
    
    if(nLeftSize != nRightSize)
        return FALSE;

    for(i = 0; i < nLeftSize; ++i)
        if(pbl[i] != pbr[i])
            return FALSE;

    return TRUE;

}// fCompareBytes()


void vPrintBytes(const void *pvData, int nSize)
{
    ASSERT(pvData && nSize > 0);
    
    const BYTE *pb = (BYTE*)pvData;

    int i;
    
    for(i = 0; i < nSize; ++i)
        printf("%02x ", pb[i]);
    printf("\n");

}// vPrintBytes()


/**
 * Converts a char string to a hash value that can be used as a key in
 * AES encrypt/decrypt function
 * @param pszStr Pointer to input char string
 * @param nLen Length of input char string excluding the terminating null byte.
 * @param pbKeyOut Pointer to output buffer
 * @param nSizeOut Size of output buffer. Must be 32bytes.
 * @return TRUE/FALSE
 */
BOOL fConvertStrToKey(const char *pszStr, int nLen, BYTE *pbKeyOut, int nSizeOut)
{
    ASSERT(pszStr && nLen > 0);
    ASSERT(pbKeyOut && nSizeOut == CRYPT_KEY_SIZE_BYTES);
    
    return fGetHash(pszStr, nLen, pbKeyOut, nSizeOut, NULL);
    
}// fConvertStrToKey()


/**
 * Generates a counter value of the required size to be used in CTR mode of encryption.
 * 
 * @param pvCtrBuffer Pointer to buffer where the output counter value will be stored
 * @param nRequiredBytes Number of bytes of counter value required
 */
void vGenCounter(BYTE *pvCtrBuffer, int nRequiredBytes)
{
    ASSERT(pvCtrBuffer && nRequiredBytes > 0);
    
    return gcry_create_nonce(pvCtrBuffer, nRequiredBytes);
    
}// vGenCounter


/**
 * Rounds up the input size to the block size and returns it.
 * @param inputSize
 * @return integer value that is rounded to block size or -1 if input was invalid.
 */
int iRoundToBlockSize(int inputSize)
{
    if(inputSize <= 0) return -1;
    
    int numBlocks = (inputSize / CRYPT_BLK_SIZE_BYTES);
    if((inputSize % CRYPT_BLK_SIZE_BYTES) > 0)
        ++numBlocks;
    
    return (numBlocks * CRYPT_BLK_SIZE_BYTES);
    
}// iRoundToBlockSize()


/**
 * Tells whether output buffer size is enough for the given input size. 
 * All sizes are in bytes. Optionally, also returns the required output
 * buffer size.
 * @param inputSize
 * @param outputSize
 * @param piReqSize
 * @return TRUE if output size is sufficient, FALSE otherwise or if input is invalid.
 */
BOOL fIsBufSizeEnough(int inputSize, int outputSize, int *piReqSize)
{
    if(inputSize < 0 || outputSize < 0)
        return FALSE;

    int nReqOutSize = iRoundToBlockSize(inputSize);
    
    if(piReqSize) *piReqSize = nReqOutSize;
    
    return (outputSize >= nReqOutSize);
    
}// fIsBufSizeEnough


/**
 * Given input data and its size in bytes, ensures that the 
 * output padded buffer is a multiple of the block size and
 * is padded with zeroes.
 * @param pvInput
 * @param nInSize
 * @param ppvPaddedBuf Address of pointer where the address of the newly
 * allocated padded buffer will be stored
 * @param nPaddedBufSize Size of the padded buffer
 * @param pierr
 * @return 
 */
BOOL fPadInput(void *pvInput, int nInSize,
               void **ppvPaddedBuf, int *pnPaddedBufSize,
               int *pierr)
{
    ASSERT(pvInput && nInSize > 0);
    ASSERT(ppvPaddedBuf && pnPaddedBufSize);
    
    int nBufSize = 0;
    void *pvNewBuf = NULL;
    
    nBufSize = iRoundToBlockSize(nInSize);
    if((pvNewBuf = malloc(nBufSize)) == NULL)
    {
        if(pierr) *pierr = ERR_NO_MEM;
        return FALSE;
    }
    
    memset(pvNewBuf, 0, nBufSize);
    memcpy(pvNewBuf, pvInput, nInSize);
    
    *ppvPaddedBuf = pvNewBuf;
    *pnPaddedBufSize = nBufSize;
    if(pierr) *pierr = ERR_NONE;
    return TRUE;
    
}// fPadInput()


/**
 * Allocates sizeBytes of memory from secure memory area and
 * sets the whole area to zero value.
 * @param sizeBytes
 * @param ppvAllocated
 * @return TRUE/FALSE depending on whether alloc request was successful or not.
 */
BOOL fSecureAlloc(int sizeBytes, void **ppvAllocated)
{
   ASSERT(ppvAllocated && sizeBytes > 0);
   
   void *pv = NULL;
   
   *ppvAllocated = NULL;
   
   if(sizeBytes <= 0)
       return FALSE;
   
   if((pv = gcry_malloc_secure(sizeBytes)) == NULL)
       return FALSE;
   
   memset(pv, 0, sizeBytes);
   *ppvAllocated = pv;
   return TRUE;

}// fSecureAlloc


/********************
 * SHA256 Functions * 
 ********************/

/**
 * Returns a hash of the input data using the SHA256 algorithm.
 * @param pvInputData Pointer to input data that must be hashed.
 * @param nInputSize Size in bytes of the input data.
 * @param pbOutBuf Pointer to buffer where the hash must be stored.
 * @param nOutBufSize Size in bytes of the output buffer. Must be 32bytes.
 * @param pierr [optional] pointer to int indicating any error value.
 * @return TRUE/FALSE
 */
BOOL fGetHash(const void *pvInputData, int nInputSize, 
        BYTE *pbOutBuf, int nOutBufSize, int *pierr)
{
    ASSERT(pvInputData && pbOutBuf);
    ASSERT(nInputSize > 0 && nOutBufSize == CRYPT_HASH_SIZE_BYTES);

    return fSHA256Worker(FALSE, NULL, pvInputData, nInputSize, pbOutBuf, pierr);

}// fGetHash()


/**
 * 
 * @param pbKey
 * @param nKeySize
 * @param pvInputData
 * @param nInputSize
 * @param pbOutBuf
 * @param nOutBufSize
 * @param pierr
 * @return 
 */
BOOL fGetHMAC(const BYTE *pbKey, int nKeySize,
        const void *pvInputData, int nInputSize, 
        BYTE *pbOutBuf, int nOutBufSize, int *pierr)
{
    ASSERT(pvInputData && pbOutBuf);
    ASSERT(nInputSize > 0 && nOutBufSize == CRYPT_HASH_SIZE_BYTES);
    ASSERT(pbKey && nKeySize == CRYPT_HASH_SIZE_BYTES);
    
    return fSHA256Worker(TRUE, pbKey, pvInputData, nInputSize, pbOutBuf, pierr);
    
}// fGetHMAC()


/**
 * 
 * @param fHMACEnable
 * @param pbKey
 * @param pvInputData
 * @param nInputSize
 * @param pbOutBuf
 * @param nOutBufSize
 * @param pierr
 * @return 
 */
static BOOL fSHA256Worker(BOOL fHMACEnable, const BYTE *pbKey,
        const void *pvInputData, int nInputSize, BYTE *pbOutBuf, int *pierr)
{
    gcry_error_t gcError = GPG_ERR_NO_ERROR;

    BYTE *pbHash = NULL;
    BYTE *pbSource = (BYTE*)pvInputData;
    
    int i;
    gcry_md_hd_t pSHA256Handle = NULL;
    unsigned int openFlag = 0;
    
    openFlag = (fHMACEnable)? GCRY_MD_FLAG_HMAC : GCRY_MD_FLAG_SECURE ;

    // open a context
    if( (gcError = gcry_md_open(&pSHA256Handle, CRYPT_ALG_HASH, openFlag)) != GPG_ERR_NO_ERROR )
    {
        logerr("fGetHash(): Error opening context: %d\n", gcError);
        goto fend;
    }
    
    // set key if HMAC is required
    if( (gcError = gcry_md_setkey(pSHA256Handle, pbKey, CRYPT_KEY_SIZE_BYTES)) != GPG_ERR_NO_ERROR )
    {
        logerr("fGetHash(): Error setting key for SHA256: %d\n", gcError);
        goto fend;
    }


    if(nInputSize < 512)
    {
        for(i = 0; i < nInputSize; ++i)
            gcry_md_putc(pSHA256Handle, pbSource[i]);
    }
    else
    {
        gcry_md_write(pSHA256Handle, pvInputData, nInputSize);
    }

    // now read the hash value
    pbHash = gcry_md_read(pSHA256Handle, CRYPT_ALG_HASH);
    if(!pbHash)
    {
        logerr("fGetHash(): gcry_md_read() failed\n");
        gcError = ERR_HASHGEN;
        goto fend;
    }

    // copy the digest into output buffer
    memcpy(pbOutBuf, pbHash, CRYPT_HASH_SIZE_BYTES);
    gcError = GPG_ERR_NO_ERROR;

    fend:
    if(pSHA256Handle)
    {
        gcry_md_close(pSHA256Handle);
        pSHA256Handle = NULL;
    }

    if(pierr) *pierr = (int)gcError;
    return (gcError == GPG_ERR_NO_ERROR);
    
}// fSHA256Worker()


/*****************
 * AES Functions * 
 *****************/

/**
 * Encrypts the bytes given as plain text and returns the cipher text
 * and counter value used as output.
 * Input size must be a multiple of block size.
 * @param pAESData
 * @return 
 */
BOOL fAESEncrypt(AES_ENCDATA *pAESData)
{
    ASSERT(pAESData);
    ASSERT(pAESData->pvInputBuf && pAESData->nInputSize > 0);
    ASSERT(pAESData->pvOutputBuf && pAESData->nOutputSize > 0);
    
    gcry_cipher_hd_t pAESHandle = NULL;
    gcry_error_t gcError = GPG_ERR_NO_ERROR;

    
    // input and output buffers must a multiple of the block size
    if(pAESData->nInputSize % CRYPT_BLK_SIZE_BYTES || 
       pAESData->nOutputSize % CRYPT_BLK_SIZE_BYTES)
    {
        pAESData->err = ERR_IN_SIZE;
        return FALSE;
    }

    // check if output buffer size is sufficient
    if(!fIsBufSizeEnough(pAESData->nInputSize, pAESData->nOutputSize, NULL))
    {
        pAESData->err = ERR_NO_MEM;
        return FALSE;
    }
    
    // open a context
    if( (gcError = gcry_cipher_open(&pAESHandle, CRYPT_ALG_CIPHER, 
            CRYPT_CIPHER_MODE, 0)) != GPG_ERR_NO_ERROR )
    {
        logerr("fAESEncrypt(): Could not open AES handle");
        goto fend;
    }

    // set the key
    logdbg("Using key: ");
    vPrintBytes(pAESData->abKey, sizeof(pAESData->abKey));
    if((gcError = gcry_cipher_setkey(pAESHandle, pAESData->abKey, sizeof(pAESData->abKey)))
            != GPG_ERR_NO_ERROR)
    {
        logerr("fAESEncrypt(): Error setting key to be used");
        pAESData->err = ERR_KEYSIZE;
        goto fend;
    }
    
    // generate and set the counter value
    vGenCounter(pAESData->abCounter, CRYPT_CTR_SIZE_BYTES);
    logdbg("Using counter: ");
    vPrintBytes(pAESData->abCounter, sizeof(pAESData->abCounter));
    if((gcError = gcry_cipher_setctr(pAESHandle, pAESData->abCounter, sizeof(pAESData->abCounter)))
            != GPG_ERR_NO_ERROR)
    {
        logerr("fAESEncrypt(): Error setting counter to be used");
        goto fend;
    }
    
    // now, encrypt
    if((gcError = gcry_cipher_encrypt(pAESHandle, pAESData->pvOutputBuf, pAESData->nOutputSize,
            pAESData->pvInputBuf, pAESData->nInputSize)) != GPG_ERR_NO_ERROR)
    {
        logerr("fAESEncrypt(): encrypt() error: %u", gcError);
        pAESData->err = ERR_ENCRYPT;
        goto fend;
    }
    
    fend:
    if(pAESHandle)
    {
        gcry_cipher_close(pAESHandle);
        pAESHandle = NULL;
    }
    
    // return TRUE if 
    return (gcError == GPG_ERR_NO_ERROR);
    
    
}// fAESEncrypt()


/**
 * 
 * @param pAESData
 * @return 
 */
BOOL fAESDecrypt(AES_DECDATA *pAESData)
{
    ASSERT(pAESData);
    ASSERT(pAESData->pvInputBuf && pAESData->nOutputSize > 0);
    ASSERT(pAESData->pvOutputBuf && pAESData->nInputSize > 0);
    
    gcry_cipher_hd_t pAESHandle = NULL;
    gcry_error_t gcError = GPG_ERR_NO_ERROR;
    
    
    // input must be a multiple of the block size
    if(pAESData->nInputSize % CRYPT_BLK_SIZE_BYTES)
    {
        pAESData->err = ERR_IN_SIZE;
        return FALSE;
    }
    
    // check for enough output buffer size
    if(pAESData->nInputSize != pAESData->nOutputSize)
    {
        pAESData->err = ERR_NO_MEM;
        return FALSE;
    }

    // open a context
    if( (gcError = gcry_cipher_open(&pAESHandle, CRYPT_ALG_CIPHER, 
            CRYPT_CIPHER_MODE, 0)) != GPG_ERR_NO_ERROR )
    {
        logerr("fAESDecrypt(): Could not open AES handle");
        goto fend;
    }

    // set the key
    logdbg("Using key: ");
    vPrintBytes(pAESData->abKey, sizeof(pAESData->abKey));
    if((gcError = gcry_cipher_setkey(pAESHandle, pAESData->abKey, sizeof(pAESData->abKey)))
            != GPG_ERR_NO_ERROR)
    {
        logerr("fAESDecrypt(): Error setting key to be used");
        pAESData->err = ERR_KEYSIZE;
        goto fend;
    }
    
    // set counter
    if((gcError = gcry_cipher_setctr(pAESHandle, pAESData->abCounter, sizeof(pAESData->abCounter)))
            != GPG_ERR_NO_ERROR)
    {
        logerr("fAESDecrypt(): Error setting counter to be used");
        goto fend;
    }
    
    // now, decrypt
    if((gcError = gcry_cipher_decrypt(pAESHandle, pAESData->pvOutputBuf, pAESData->nOutputSize,
            pAESData->pvInputBuf, pAESData->nInputSize)) != GPG_ERR_NO_ERROR)
    {
        logerr("fAESDecrypt(): decrypt() error: %u", gcError);
        pAESData->err = ERR_DECRYPT;
        goto fend;
    }
    
    fend:
    if(pAESHandle)
    {
        gcry_cipher_close(pAESHandle);
        pAESHandle = NULL;
    }
    
    // return TRUE if err == 0
    return (gcError == GPG_ERR_NO_ERROR);
    
}// fAESDecrypt()
