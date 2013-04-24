#ifndef _SDHANDLER_H
#define _SDHANDLER_H

// standard
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

// sockets
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "defs.h"
#include "packet.h"
#include "assert.h"
#include "sdbg.h"

/* function prototypes */
BOOL PE_fSendPacket(int iSockID, void *pvPacket, int nSize, int *piReturnVal);

BOOL PE_fRecvPacket(int iSockID, void *pvPacketBuf, int nSize, int *piReturnVal);

//BOOL PE_fTestSockRead(int iSockID, int iTimeoutSec, int iTimeoutMicroSec, int *piRetVal);

#endif // _SDHANDLER_H
