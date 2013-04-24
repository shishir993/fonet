
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
    ASSERT(nCounterSize == CRYPT_CTR_SIZE_BYTES 0 && nCipherSize > 0);
    
    void *pvmem = NULL;
    int nTotalSize = CRYPT_CTR_SIZE_BYTES + sizeof(int) + nCipherSize;
    
    // first, alloc enough contiguous memory
    if((pvmem = malloc(nTotalSize)) == NULL)
    {
        logerr("pConstructMessage(): malloc()");
        return NULL;
    }
    
    // now copy: counter, size, ciphertext
    memcpy(pvmem, pbCounter, CRYPT_CTR_SIZE_BYTES);
    *(pvmem+CRYPT_CTR_SIZE_BYTES) = nCipherSize;
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
        BYTE *pbKey, int nKeySize)
{
    ASSERT(pvMessage && pbKey);
    ASSERT(nMessageSize > 0 && nKeySize == CRYPT_KEY_SIZE_BYTES);
    
    void *pvmem = NULL;
    int nTotalSize;
    
    nTotalSize = nMessageSize + CRYPT_HASH_SIZE_BYTES;
    if((pvmem = malloc(nTotalSize)) == NULL)
    {
        logerr("pConstructPacket(): malloc()");
        return NULL;
    }
    
    // copy the message first
    memcpy(pvmem, pvMessage, nMessageSize);
    
    // calculate HMAC using given key
    if(!fGetHMAC(pbKey, nKeySize, pvMessage, nMessageSize,
            pvmem+nMessageSize, CRYPT_HASH_SIZE_BYTES))
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
void* pConstructCipherText(int mid, const void *pvMessageContents, int *pnCipherSize)
{
    
}