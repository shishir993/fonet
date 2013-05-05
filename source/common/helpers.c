
#include <unistd.h>

#include "helpers.h"


// Structure to store arguments to fConstructCipherText()
typedef struct _encdata {
    // input
    int mid;
    void *pvMessageContents;
    int nMsgContentsSize;
    
    BYTE *pbKey;
    
    // output
    BYTE abCounterOut[CRYPT_CTR_SIZE_BYTES];
    void *pvCipherOut;
    int nCipherSizeOut;
}ENC_DATA;


// File-local Functions
static BOOL fCheckIntegrity(BYTE *pbKey, void *pvMessage, int nMessageSize, BYTE *pbHMAC);

static void* pConstructMessage(const BYTE *pbCounter,
        int nCipherSize, const void *pvCiphertext, int *pnTotalSize);

static void* pvCreatePacket(const void *pvMessage, int nMessageSize,
        BYTE *pbHMACKey, int *pnTotalPacketSize);

static BOOL fConstructCipherText(ENC_DATA *pEncData);
static BOOL fIsPacketNotTampered(void *pvPacket, int nPacketSize, BYTE *pbHMACKey);




BOOL fLoadSharedKeyFile(const char *pszFilepath, SHARED_KEY **ppskBuffer)
{
    ASSERT(pszFilepath && ppskBuffer);

    int fd = -1;
    ssize_t uBytesRead = 0;
   
    SHARED_KEY *pskSecMem = NULL;
    
    
    if(!fSecureAlloc(sizeof(SHARED_KEY), (void**)&pskSecMem))
    { logwarn("Secure alloc failed!"); goto error_return; }
    
    if((fd = open(pszFilepath, O_RDONLY, 0)) == -1)
    {
        logerr("fLoadSharedKeyFile(): open() ");
        goto error_return;
    }
    
    if((uBytesRead = read(fd, pskSecMem, sizeof(SHARED_KEY))) != sizeof(SHARED_KEY)) 
    {
        logerr("fLoadSharedKeyFile(): read() ");
        goto error_return;
    }
    
//#ifdef _DEBUG
//    printf("fLoadSharedKeyFile(): Read from file...\n");
//    printf("Alice: %s\n", pskSecMem->szAlice);
//    printf("Bob  : %s\n", pskSecMem->szBob);
//    printf("Key  : ");
//    vPrintBytes(pskSecMem->abKey, CRYPT_KEY_SIZE_BYTES);
//#endif

    close(fd);
    *ppskBuffer = pskSecMem;
    return TRUE;
    
    error_return:
    if(fd != -1) close(fd);
    *ppskBuffer = NULL;
    return FALSE;
    
}


/**
 * Given MID, Message Contents and the Message Contents Size, along 
 * with encryption and HMAC keys, it creates a packet that can be sent
 * over a socket. Message contents are encrypted and the 'Message' part
 * has a HMAC attached to it. Caller responsible for freeing returned 
 * buffer.
 * 
 * @param mid
 * @param pMessageContents
 * @param mcSize
 * @param pbKeyEnc
 * @param nKeyEncSize
 * @param pbKeyHash
 * @param nKeyHashSize
 * @param pnPacketSizeOut
 * 
 * @return 
 */
void* pvConstructPacket(int mid, void *pMessageContents, int mcSize,
        BYTE *pbKeyEnc, int nKeyEncSize,
        BYTE *pbKeyHash, int nKeyHashSize,
        int *pnPacketSizeOut)
{
    
    ASSERT(pbKeyEnc && nKeyEncSize == CRYPT_KEY_SIZE_BYTES);
    ASSERT(pbKeyHash);
    ASSERT(nKeyHashSize == CRYPT_KEY_SIZE_BYTES);
    ASSERT(pnPacketSizeOut);
    
    ENC_DATA encData;
    
    int nTotalMsgSize = 0;
    int nPacketSize = 0;
    
    void *pMessage = NULL;
    void *pPacket = NULL;
    
    // first, generate ciphertext
    encData.mid = mid;
    if(pMessageContents)
    {
        encData.pvMessageContents = pMessageContents;
        encData.nMsgContentsSize = mcSize;
    }
    else
    {
        encData.pvMessageContents = NULL;
        encData.nMsgContentsSize = 0;
    }
    encData.pbKey = pbKeyEnc;
    
    if(!fConstructCipherText(&encData))
    {
        logwarn("vCreatePacket(): Could not construct ciphertext");
        goto error_return;
    }
    
    // now, construct message
    pMessage = pConstructMessage(encData.abCounterOut, 
            encData.nCipherSizeOut, encData.pvCipherOut, &nTotalMsgSize);
    if(pMessage == NULL)
    {
        logwarn("vCreatePacket(): Could not construct message");
        goto error_return;
    }
    
    // now, construct packet
    pPacket = pvCreatePacket(pMessage, nTotalMsgSize, pbKeyHash, &nPacketSize);
    if(pPacket == NULL)
    {
        logwarn("vCreatePacket(): Could not construct packet");
        goto error_return;
    }
    free(encData.pvCipherOut);
    free(pMessage);
    *pnPacketSizeOut = nPacketSize;
    return pPacket;
    
    error_return:
    if(encData.pvCipherOut) free(encData.pvCipherOut);
    if(pMessage) free(pMessage);
    if(pPacket) free(pPacket);
    return NULL;

}// pvConstructPacket()



/**
 * Packet received over a socket is deconstructed into MID,
 * Message Contents and Message Contents Size. Caller responsible
 * for freeing message contents buffer.
 * 
 * @param pbDecryptKey
 * @param pbHMACKey
 * @param pvPacket
 * @param nPacketSize
 * @param piMIDOut
 * @param piMCSizeOut
 * @param ppvMessageContentsOut
 * 
 * @return 
 */
BOOL fDeconstructPacket(BYTE *pbDecryptKey, BYTE *pbHMACKey,
        void *pvPacket, int nPacketSize, 
        int *piMIDOut, int *piMCSizeOut, void **ppvMessageContentsOut)
{
    ASSERT(pbDecryptKey && pbHMACKey);
    ASSERT(pvPacket && nPacketSize > 0);
    ASSERT(piMIDOut && piMCSizeOut && ppvMessageContentsOut);
    
    
    BYTE *pbCounter;
    int *piSize;
    void *pvCipherText;
    int nMsgSize = 0;
    
    void *pvPlainText;
    int *piDecrypted;
    int nPlainTextSize;
    AES_DECDATA aesDecData;
    
    
    pbCounter = pvPacket;
    piSize = pvPacket+CRYPT_CTR_SIZE_BYTES;
    pvCipherText = pvPacket + CRYPT_CTR_SIZE_BYTES + sizeof(int);
    
    nMsgSize = CRYPT_CTR_SIZE_BYTES + sizeof(int) + *piSize;
    loginfo("fDeconstructPacket(): msgSize %d", nMsgSize);
    if(!fIsPacketNotTampered(pvPacket, nMsgSize+CRYPT_HASH_SIZE_BYTES, pbHMACKey))
    {
        logwarn("Packet was tampered in transit!");
        goto error_return;
    }
    
    // alloc memory to hold decrypted data
    if((nPlainTextSize = iRoundToBlockSize(*piSize)) <= 0)
    {
        logwarn("fGetMIDMsgContents(): Error in round off");
        goto error_return;
    }
    
    if((pvPlainText = malloc(nPlainTextSize)) == NULL)
    {
        logerr("fGetMIDMsgContents(): malloc() ");
        goto error_return;
    }
    
    //now, decrypt
    memcpy(aesDecData.abCounter, pbCounter, CRYPT_CTR_SIZE_BYTES);
    aesDecData.pvInputBuf = pvCipherText;
    aesDecData.nInputSize = *piSize;
    aesDecData.pbKey = pbDecryptKey;
    aesDecData.nKeySize = CRYPT_KEY_SIZE_BYTES;
    aesDecData.pvOutputBuf = pvPlainText;
    aesDecData.nOutputSize = nPlainTextSize;
    
    if(!fAESDecrypt(&aesDecData))
    {
        logwarn("Error in decryption!");
        goto error_return;
    }
    
    piDecrypted = pvPlainText;
    *piMIDOut = *piDecrypted;
    *piMCSizeOut = *(piDecrypted+1);
    if(*piMCSizeOut > 0)
        *ppvMessageContentsOut = pvPlainText+sizeof(int)+sizeof(int);
    else
        *ppvMessageContentsOut = NULL;
    return TRUE;
    
    error_return:
    return FALSE;
    
}// fDeconstructPacket



/**
 * 
 * @param pMessage
 * @param nMessageSize
 * @param pbHMAC
 * @param nHMACSize
 * @return 
 */
static BOOL fCheckIntegrity(BYTE *pbHMACKey, void *pvMessage, int nMessageSize, BYTE *pbHMAC)
{
    ASSERT(pvMessage && pbHMACKey && pbHMAC);

    int err = 0;
    BYTE abDigestNow[CRYPT_HASH_SIZE_BYTES];

    memset(abDigestNow, 0, sizeof(abDigestNow));

    // calculate new digest
    if(!fGetHMAC(pbHMACKey, CRYPT_KEY_SIZE_BYTES,
            pvMessage, nMessageSize, 
            abDigestNow, CRYPT_HASH_SIZE_BYTES, &err))
    {
        logwarn("fCheckIntegrity(): Failed to calculate hash!!!");
        return FALSE;
    }

    return fCompareDigests(pbHMAC, CRYPT_HASH_SIZE_BYTES, abDigestNow, sizeof(abDigestNow));

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
static void* pConstructMessage(const BYTE *pbCounter, 
        int nCipherSize, const void *pvCiphertext, int *pnTotalSize)
{
    ASSERT(pbCounter && pvCiphertext);
    ASSERT(nCipherSize > 0);
    
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
    
#ifdef _DEBUG
    printf("pConstructMessage()::::\n");
    printf("Counter %p: ", pvmem);
    vPrintBytes(pvmem, CRYPT_CTR_SIZE_BYTES);
    printf("Size    %p: %d\n", pvmem+CRYPT_CTR_SIZE_BYTES, *((int*)(pvmem+CRYPT_CTR_SIZE_BYTES)));
    printf("Ciphertext %p: ", pvmem+CRYPT_CTR_SIZE_BYTES+sizeof(int));
    vPrintBytes(pvmem+CRYPT_CTR_SIZE_BYTES+sizeof(int), nCipherSize);
#endif
    
    if(pnTotalSize) *pnTotalSize = nTotalSize;
    return pvmem;
    
}// pConstructMessage


/**
 * 
 * @param pvMessage
 * @param nMessageSize
 * @param pbHMACKey
 * @param nHMACKeySize
 * @param pnTotalPacketSize
 * @return 
 */
static void* pvCreatePacket(const void *pvMessage, int nMessageSize,
        BYTE *pbHMACKey, int *pnTotalPacketSize)
{
    ASSERT(pvMessage && pbHMACKey);
    ASSERT(nMessageSize > 0);
    
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
    if(!fGetHMAC(pbHMACKey, CRYPT_KEY_SIZE_BYTES, pvMessage, nMessageSize,
            pvmem+nMessageSize, CRYPT_HASH_SIZE_BYTES, NULL))
    {
        free(pvmem);
        return NULL;
    }
    
#ifdef _DEBUG
    printf("pConstructPacket()::::\n");
    printf("Message %p(%d): ", pvmem, nMessageSize);
    vPrintBytes(pvmem, nMessageSize);
    printf("HMAC %p: ", pvmem+nMessageSize);
    vPrintBytes(pvmem+nMessageSize, CRYPT_HASH_SIZE_BYTES);
#endif
    
    *pnTotalPacketSize = nTotalSize;
    return pvmem;
    
}// pvCreatePacket()


/**
 * 
 * @param mid
 * @param pvMessageContents
 * @param pnCipherSize
 * @return 
 */
static BOOL fConstructCipherText(ENC_DATA *pEncData)
{
    ASSERT(pEncData);
    ASSERT(pEncData->pbKey);
    
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
    ++iptr;
    *iptr = pEncData->nMsgContentsSize;
    if(pEncData->pvMessageContents)
    {
        ++iptr;
        memcpy(iptr, pEncData->pvMessageContents, pEncData->nMsgContentsSize);
    }
    
    
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


static BOOL fIsPacketNotTampered(void *pvPacket, int nPacketSize, BYTE *pbHMACKey)
{
    ASSERT(pvPacket);
    ASSERT(nPacketSize > CRYPT_HASH_SIZE_BYTES);
    
#ifdef _DEBUG
    loginfo("HMAC: ");
    vPrintBytes(pvPacket+nPacketSize-CRYPT_HASH_SIZE_BYTES, CRYPT_HASH_SIZE_BYTES);
#endif
    
    return fCheckIntegrity(pbHMACKey, pvPacket, nPacketSize-CRYPT_HASH_SIZE_BYTES,
            pvPacket+nPacketSize-CRYPT_HASH_SIZE_BYTES);
    
}// fIsPacketNotTampered()


/**
 * 
 * @param pszBuffer
 * @param nBufLen Includes the terminating NULL character
 * @return 
 */
BOOL fReadLineFromStdin(char *pszBuffer, int nBufLen) 
{
    ASSERT(pszBuffer && nBufLen > 0);

    int nlen = 0;
    char ch;

    if ((ch = getchar()) != '\n')
        ungetc(ch, stdin);

    while (nlen < nBufLen && (ch = getchar()) != '\n')
        pszBuffer[nlen++] = ch;
    pszBuffer[nlen] = 0;
    return TRUE;
}
