
#include "packet_exchange.h"


BOOL PE_fSendPacket(int iSockID, void *pvPacket, int nSize, int *piReturnVal)
{
    ASSERT(iSockID > -1 && pvPacket);
    ASSERT(nSize > 0);

    int nSentBytes = 0;
    int nTotalSentBytes = 0;


    while(nTotalSentBytes < nSize)
    {
        nSentBytes = send(iSockID, ((char*)pvPacket)+nTotalSentBytes, nSize-nTotalSentBytes, 0);
        if(nSentBytes < 0)
        {
            if(piReturnVal) *piReturnVal = errno;
            return FALSE;
        }
        else if(nSentBytes == 0)
        {
            if(piReturnVal) *piReturnVal = ERR_SOCKET_DOWN;
            return FALSE;
        }

        nTotalSentBytes += nSentBytes;

    }// while

    //logdbg("PE_fSendPacket(): Successfully sent %d bytes from socket %d", nTotalSentBytes, iSockID);

    if(piReturnVal) *piReturnVal = 0;
    return TRUE;

}// PE_fSendPacket()


BOOL PE_fRecvPacket(int iSockID, void *pvPacketBuf, int nSize, int *piReturnVal)
{
    ASSERT(iSockID > -1 && pvPacketBuf);
    ASSERT(nSize > 0);

    int nRecvBytes = 0;
    int nTotalRecvBytes = 0;


    while(nTotalRecvBytes < nSize)
    {
        nRecvBytes = recv(iSockID, ((char*)pvPacketBuf)+nTotalRecvBytes, nSize-nTotalRecvBytes, 0);
        if(nRecvBytes < 0)
        {
            if(piReturnVal) *piReturnVal = errno;
            return FALSE;
        }
        else if(nRecvBytes == 0)
        {
            if(piReturnVal) *piReturnVal = ERR_SOCKET_DOWN;
            return FALSE;
        }

        nTotalRecvBytes += nRecvBytes;

    }// while

    //logdbg("PE_fRecvPacket(): Successfully received %d bytes from socket %d", nTotalRecvBytes, iSockID);

    if(piReturnVal) *piReturnVal = 0;
    return TRUE;

}// PE_fRecvPacket()


BOOL PE_fTestSockRead(int iSockID, int iTimeoutSec, int iTimeoutMicroSec, int *piRetVal)
{
    ASSERT(iSockID >= 0);
    ASSERT(iTimeoutSec >= 0 && iTimeoutMicroSec >= 0);

    fd_set fdSetRead;
    struct timeval tvTimeOut;

    FD_ZERO(&fdSetRead);
    FD_SET(iSockID, &fdSetRead);

    tvTimeOut.tv_sec = iTimeoutSec;
    tvTimeOut.tv_usec = iTimeoutMicroSec;

    if( select(iSockID+1, &fdSetRead, NULL, NULL, &tvTimeOut) == -1 )
    {
        logerr("PE_fTestSockRead(): select() failed");
        if(piRetVal) *piRetVal = errno;
        return FALSE;
    }
    
    if(piRetVal) *piRetVal = 0;

    if( FD_ISSET(iSockID, &fdSetRead) )
        return TRUE;

    return FALSE;

}// PE_fTestSockRead()

