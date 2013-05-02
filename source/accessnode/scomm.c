
#include "scomm.h"


extern struct in_addr g_iaServAddr;
extern char *pszServAddrStr;

static int lg_iServSocket = -1;
static BOOL lg_abSRBuffer[SR_BUFSIZE];


BOOL fConnectToServer()
{
    int yes = 1;
    struct sockaddr_in saServAddr;
    
    int nTries = 0;
    
    
    // create a socket
    if( (lg_iServSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
    {
        logerr("fConnectToServer(): socket()");
        goto error_return;
    }

    // set it to reuse address
    if( setsockopt(lg_iServSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 )
    {
        logwarn("fConnectToServer(): setsockopt() failed %s\n", strerror(errno));
        // goto error_return;
        // not a critical error
    }

    // setup the server address structure
    memset(&saServAddr, 0, sizeof(struct sockaddr_in));

    saServAddr.sin_family = AF_INET;
    saServAddr.sin_port = htons(SERVR_LPORT);
    saServAddr.sin_addr.s_addr = g_iaServAddr.s_addr;

    while(nTries < 5)
    {
        loginfo("Connecting to server. Try %d...", nTries);
        if( connect(lg_iServSocket, (struct sockaddr*)&saServAddr,
                            sizeof(struct sockaddr_in)) < 0 )
        {
            loginfo("Failed: connect() %s", strerror(errno));
            ++nTries;
            sleep(5);
            continue;
        }
        break;
    }
    
    if(nTries >= 5)
    {
        logerr("Could not connect to server");
        goto error_return;
    }
    
    return TRUE;

    error_return:
    if(lg_iServSocket != -1) { close(lg_iServSocket); lg_iServSocket = -1; }
    return FALSE;
    
}// fConnectToServer()


void vServCloseSocket()
{
    if(lg_iServSocket != -1)
        close(lg_iServSocket);
    lg_iServSocket = -1;
}


BOOL fSendToServer(void *pvPacket, int nPacketSize)
{
    ASSERT(pvPacket && nPacketSize > 0);
    
    int iRetVal = 0;
    
    
    memset(lg_abSRBuffer, 0, sizeof(lg_abSRBuffer));
    memcpy(lg_abSRBuffer, pvPacket, nPacketSize);
    
    if(!PE_fSendPacket(lg_iServSocket, lg_abSRBuffer, sizeof(lg_abSRBuffer), &iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            logwarn("fSendToServer(): Server closed socket unexpectedly");
        else
            logwarn("fSendToServer(): error (%s)", strerror(iRetVal));
        return FALSE;
    }
    return TRUE;
    
}// fSendToServer()


BOOL fRecvFromServer(void *pvBuffer, int nBufSize)
{
    ASSERT(pvBuffer && nBufSize >= sizeof(lg_abSRBuffer));
    
    int iRetVal = 0;
    
    
    memset(lg_abSRBuffer, 0, sizeof(lg_abSRBuffer));
    
    if(!PE_fRecvPacket(lg_iServSocket, lg_abSRBuffer, sizeof(lg_abSRBuffer), &iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            logwarn("fRecvFromServer(): Server closed socket unexpectedly");
        else
            logwarn("fRecvFromServer(): error (%s)", strerror(iRetVal));
        return FALSE;
    }
    
    memcpy(pvBuffer, lg_abSRBuffer, nBufSize);
    return TRUE;
    
}// fRecvFromServer()
