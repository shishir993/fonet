
#include "scomm.h"

extern int g_nServerPort;
extern struct in_addr g_iaServAddr;
extern char *pszServAddrStr;

static int lg_iServSocket = -1;


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
    saServAddr.sin_port = htons(g_nServerPort);
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
