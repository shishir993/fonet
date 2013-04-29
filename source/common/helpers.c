
#include "helpers.h"


/**
 * 
 * @param pMessage
 * @param nMessageSize
 * @param pbHMAC
 * @param nHMACSize
 * @return 
 */
BOOL fCheckIntegrity(BYTE *pbKey, int nKeySize,
        void *pvMessage, int nMessageSize, 
        BYTE *pbHMAC, int nHMACSize)
{
    ASSERT(pvMessage && pbKey && pbHMAC);
    ASSERT(nKeySize == CRYPT_KEY_SIZE_BYTES && nHMACSize == CRYPT_HASH_SIZE_BYTES);

    int err = 0;
    BYTE abDigestNow[CRYPT_HASH_SIZE_BYTES];

    memset(abDigestNow, 0, sizeof(abDigestNow));

    // calculate new digest
    if(!fGetHash(pvMessage, nMessageSize, abDigestNow, nHMACSize, &err))
    {
        logwarn("fCheckIntegrity(): Failed to calculate hash!!!");
        return FALSE;
    }

    return fCompareDigests(pbHMAC, nHMACSize, abDigestNow, sizeof(abDigestNow));

}// fCheckIntegrity()


/**
 * 
 * @param pbCounter
 * @param nCounterSize
 * @param nCipherSize
 * @param pvCiphertext
 * @param pnTotalSize
 * @return 
 */
void* pConstructMessage(const BYTE *pbCounter, int nCounterSize, 
        int nCipherSize, const void *pvCiphertext, int *pnTotalSize)
{
    ASSERT(pbCounter && pvCiphertext);
    ASSERT(nCounterSize == CRYPT_CTR_SIZE_BYTES && nCipherSize > 0);
    
    void *pvmem = NULL;
    int *iptr = NULL;
    
    int nTotalSize = CRYPT_CTR_SIZE_BYTES + sizeof(int) + nCipherSize;
    if(nTotalSize <= 0)
    {
        logerr("pConstructMessage(): Integer overflow!!");
        return NULL;
    }
    
    // first, alloc enough contiguous memory
    if((pvmem = malloc(nTotalSize)) == NULL)
    {
        logerr("pConstructMessage(): malloc()");
        return NULL;
    }
    
    // now copy: counter, size, ciphertext
    memcpy(pvmem, pbCounter, CRYPT_CTR_SIZE_BYTES);
    iptr = pvmem+CRYPT_CTR_SIZE_BYTES;
    *iptr = nCipherSize;
    memcpy(pvmem+CRYPT_CTR_SIZE_BYTES+sizeof(int), pvCiphertext, nCipherSize);
    
    if(pnTotalSize) *pnTotalSize = nTotalSize;
    return pvmem;
    
}// pConstructMessage


/**
 * 
 * @param pvMessage
 * @param nMessageSize
 * @param pbKey
 * @param nKeySize
 * @return 
 */
void* pConstructPacket(const void *pvMessage, int nMessageSize,
        BYTE *pbHMACKey, int nHMACKeySize, int *pnTotalPacketSize)
{
    ASSERT(pvMessage && pbHMACKey);
    ASSERT(nMessageSize > 0 && nHMACKeySize == CRYPT_KEY_SIZE_BYTES);
    
    void *pvmem = NULL;
    int nTotalSize;
    
    nTotalSize = nMessageSize + CRYPT_HASH_SIZE_BYTES;
    if(nTotalSize <= 0)
    {
        logerr("pConstructPacket(): Integer overflow!!");
        return NULL;
    }
    
    if((pvmem = malloc(nTotalSize)) == NULL)
    {
        logerr("pConstructPacket(): malloc()");
        return NULL;
    }
    
    // copy the message first
    memcpy(pvmem, pvMessage, nMessageSize);
    
    // calculate HMAC using given key
    if(!fGetHMAC(pbHMACKey, nHMACKeySize, pvMessage, nMessageSize,
            pvmem+nMessageSize, CRYPT_HASH_SIZE_BYTES, NULL))
    {
        free(pvmem);
        return NULL;
    }
    
    return pvmem;
    
}// pConstructPacket()


/**
 * 
 * @param mid
 * @param pvMessageContents
 * @param pnCipherSize
 * @return 
 */
BOOL fConstructCipherText(ENC_DATA *pEncData)
{
    ASSERT(pEncData);
    ASSERT(pEncData->pvMessageContents && pEncData->nMsgContentsSize > 0);
    ASSERT(pEncData->pbKey && pEncData->nKeySize == CRYPT_KEY_SIZE_BYTES);
    
    BOOL fret = TRUE;
    void *pvmem = NULL;
    void *pvPaddedInput = NULL;
    int *iptr = NULL;
    void *pvCiphertext = NULL;
    
    AES_ENCDATA aesEncData;
    
    int nTotalSize;
    int nPaddedSize;
    
    
    nTotalSize = sizeof(int) + sizeof(int) + pEncData->nMsgContentsSize;
    if(nTotalSize <= 0)
    {
        logerr("pConstructCipherText(): Integer overflow!!");
        return FALSE;
    }
    
    if((pvmem = malloc(nTotalSize)) == NULL)
    {
        logerr("pConstructCipherText(): malloc()");
        return FALSE;
    }
    
    iptr = (int*)pvmem;
    
    // copy one by one: mid, size, message contents
    *iptr = pEncData->mid;
    iptr += sizeof(int);
    *iptr = pEncData->nMsgContentsSize;
    iptr += sizeof(int);
    memcpy(iptr, pEncData->pvMessageContents, pEncData->nMsgContentsSize);
    
    /* Now, calculate padded input size and get the 
     * input data padded. This padded input size will
     * be equal to the output cipher size.
     */
    if(!fPadInput(pvmem, nTotalSize, &pvPaddedInput, &nPaddedSize, NULL))
    {
        logerr("pConstructCipherText(): fPadInput() failed!");
        fret = FALSE;
        goto fend;
    }
    
    if((pvCiphertext = malloc(nPaddedSize)) == NULL)
    {
        logerr("pConstructCipherText(): ");
        fret = FALSE;
        goto fend;
    }
    
    // now, for the encryption
    aesEncData.pbKey = pEncData->pbKey;
    aesEncData.nKeySize = CRYPT_KEY_SIZE_BYTES;
    aesEncData.pvInputBuf = pvPaddedInput;
    aesEncData.nInputSize = nPaddedSize;
    aesEncData.pvOutputBuf = pvCiphertext;
    aesEncData.nOutputSize = nPaddedSize;
    
    if(!fAESEncrypt(&aesEncData))
    {
        logerr("pConstructCipherText(): Encryption failed!");
        fret = FALSE;
        goto fend;
    }
    
    memcpy(pEncData->abCounterOut, aesEncData.abCounter, CRYPT_CTR_SIZE_BYTES);
    pEncData->nCipherSizeOut = nPaddedSize;
    pEncData->pvCipherOut = pvCiphertext;
    
    fend:
    if(pvPaddedInput) {free(pvPaddedInput); pvPaddedInput = NULL;}
    if(pvmem) {free(pvmem); pvPaddedInput = NULL;}
    return fret;

}// fConstructCipherText()


void* pvCreatePacket(int mid, void *pMessageContents, int mcSize,
        BYTE *pbKeyEnc, int nKeyEncSize,
        BYTE *pbKeyHash, int nKeyHashSize,
        int *pnPacketSize)
{
    
    ASSERT(pMessageContents);
    ASSERT(mcSize > 0);
    ASSERT(pbKeyEnc && nKeyEncSize == CRYPT_KEY_SIZE_BYTES);
    ASSERT(pbKeyHash && nKeyHashSize == CRYPT_KEY_SIZE_BYTES);
    
    ENC_DATA encData;
    
    int nTotalMsgSize = 0;
    int nPacketSize = 0;
    
    void *pMessage = NULL;
    void *pPacket = NULL;
    
    // first, generate ciphertext
    encData.mid = mid;
    encData.pvMessageContents = pMessageContents;
    encData.nMsgContentsSize = mcSize;
    encData.pbKey = pbKeyEnc;
    encData.nKeySize = CRYPT_KEY_SIZE_BYTES;
    
    if(!fConstructCipherText(&encData))
    {
        logwarn("vCreatePacket(): Could not construct ciphertext");
        goto error_return;
    }
    
    // now, construct message
    pMessage = pConstructMessage(encData.abCounterOut, CRYPT_CTR_SIZE_BYTES,
            encData.nCipherSizeOut, encData.pvCipherOut, &nTotalMsgSize);
    if(pMessage == NULL)
    {
        logwarn("vCreatePacket(): Could not construct message");
        goto error_return;
    }
    
    // now, construct packet
    pPacket = pConstructPacket(pMessage, nTotalMsgSize, pbKeyHash, CRYPT_KEY_SIZE_BYTES,
            &nPacketSize);
    if(pPacket == NULL)
    {
        logwarn("vCreatePacket(): Could not construct packet");
        goto error_return;
    }
    free(encData.pvCipherOut);
    free(pMessage);
    *pnPacketSize = nPacketSize;
    return pPacket;
    
    error_return:
    if(encData.pvCipherOut) free(encData.pvCipherOut);
    if(pMessage) free(pMessage);
    if(pPacket) free(pPacket);
    return NULL;

}// vGeneratePacket()


BOOL fPasswdIntoHashTable(HTABLE *pht, const char *pszFilepath, int *pierr)
{
    ASSERT(pht && pszFilepath);
    
    int fd = -1;
    USER_PASSWD upData;
    ssize_t uBytesRead = 0;
    
    int nRecord = 0;
    
    if((fd = open(pszFilepath, O_RDONLY, 0)) == -1)
    {
        logerr("Could not open file %s ", pszFilepath);
        return FALSE;
    }
    
    while((uBytesRead = read(fd, &upData, sizeof(USER_PASSWD))) == sizeof(USER_PASSWD))
    {
        // insert into hashtable
//        if(!HT_fInsert_UV(pht, ))
//#ifdef _DEBUG
//        printf("Record %d\n", nRecord++);
//        printf("Username: %s\n", upData.szUsername);
//        printf("Salt    : ");
//        vPrintBytes(upData.abSalt, CRYPT_SALT_SIZE_BYTES);
//        printf("Hashed  : ");
//        vPrintBytes(upData.abPasswd, CRYPT_HASH_SIZE_BYTES);
//#endif
//        DBG_MEMSET(&upData, sizeof(USER_PASSWD));
    }
    
    return FALSE;
    
}// fPasswdIntoHashTable()
