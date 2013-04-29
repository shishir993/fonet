#ifndef _HELPERS_H
#define _HELPERS_H


// open()
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "assert.h"
#include "sdbg.h"
#include "packet.h"
#include "cutils.h"
#include "hashtable.h"



typedef struct _encdata {
    // input
    int mid;
    void *pvMessageContents;
    int nMsgContentsSize;
    
    BYTE *pbKey;
    int nKeySize;
    
    // output
    BYTE abCounterOut[CRYPT_CTR_SIZE_BYTES];
    void *pvCipherOut;
    int nCipherSizeOut;
}ENC_DATA;

BOOL fCheckIntegrity(BYTE *pbKey, int nKeySize,
        void *pvMessage, int nMessageSize, 
        BYTE *pbHMAC, int nHMACSize);

void* pConstructMessage(const BYTE *pbCounter, int nCounterSize, 
        int nCipherSize, const void *pvCiphertext, int *pnTotalSize);

void* pConstructPacket(const void *pvMessage, int nMessageSize,
        BYTE *pbHMACKey, int nHMACKeySize, int *pnTotalPacketSize);

BOOL fConstructCipherText(ENC_DATA *pEncData);

void* pvCreatePacket(int mid, void *pMessageContents, int mcSize,
        BYTE *pbKeyEnc, int nKeyEncSize,
        BYTE *pbKeyHash, int nKeyHashSize,
        int *pnPacketSize);

BOOL fPasswdIntoHashTable(HTABLE *pht, const char *pszFilepath, int *pierr);


#endif // _HELPERS_H
