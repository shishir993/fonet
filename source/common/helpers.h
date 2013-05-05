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


BOOL fLoadSharedKeyFile(const char *pszFilepath, SHARED_KEY **ppskBuffer);


void* pvConstructPacket(int mid, void *pMessageContents, int mcSize,
        BYTE *pbKeyEnc, int nKeyEncSize,
        BYTE *pbKeyHash, int nKeyHashSize,
        int *pnPacketSize);

BOOL fDeconstructPacket(BYTE *pbDecryptKey, BYTE *pbHMACKey,
        void *pvPacket, int nPacketSize, 
        int *piMIDOut, int *piMCSizeOut, void **ppvMessageContentsOut);

BOOL fReadLineFromStdin(char *pszBuffer, int nBufLen);

#endif // _HELPERS_H
