
#include <sys/time.h>

#include "clihandler.h"
#include "scomm.h"


#define MAX_TOKENS  32
#define FILE_TOKEN  "../etc/anode_tokens.dat"

#define SECS_PER_DAY    86400   // (60*60*24)


extern int g_nListenPort;
extern SHARED_KEY  *g_pCliSharedKey;    // to store client-accessnode shared keys
extern BYTE *g_pbCliHMACKey;            // hmac key for client: hash(cli shared key)
extern BYTE *g_pbANSecretKey;
extern SHARED_KEY  *g_pServerSK;       // pointer to accessnode-server shared key
extern BYTE *g_pbServerHMACKey;        // hmac key for server: hash(serv shared key)

static BYTE *g_pbCliSessionKey;
static BYTE *g_pbCliSessionHMACKey;

static int lg_iClientSocket;
static char lg_szClientIP[INET_ADDRSTRLEN];
static char lg_szServerIP[INET_ADDRSTRLEN];

static BYTE lg_abSRBuffer[SR_BUFSIZE];




// File-local functions
static BOOL fWaitForHello();
static BOOL fDoHandshake();
static BOOL fWaitForLogin(void **ppvLoginCred, int *piLCSize);
static BOOL fWaitForServerApproval(int *pistate, void *pvLoginCred, int lcSize,
        void **ppvCliPacketOut, int *pnCliPacketSizeOut, void **ppvToFree);
static BOOL fHandleClientLoginFail();
static BOOL fBeginSession(void *pvCliPacket, int nCliPacketSize, void *pvToFree);
static BOOL fDoDataForward();
static BOOL fTerminateConn();
static BOOL fDoCleanUp();

static void vWriteToBuffer(void *pvInput, int nInputSize);
static BOOL fSendBuffer(int *piError);
static BOOL fRecvBuffer(int *piError);
static void vFreePlainTextBuffer(void **pvMessageContents);

BOOL fCreateAccessToken(const char *pszClientIP, const char *pszServerIP,
        ATOKEN *pATokenOut);
BOOL fConstSendServerPacket(const char *pszClientIP, int mid, void *pvCliPacket, int nCliPacketSize);
BOOL fConstSendClientPacket(int mid, void *pvServPacket, int nServPacketSize);

/**
 * 
 * @param piCliSocket
 * @return 
 */
BOOL fStartClientListen(int *piCliSocket)
{
    ASSERT(piCliSocket);

    int yes = 1;
    int iListenSocket = -1;
    struct sockaddr_in myAddr;
    
    int iNewSocket = -1;
    struct timeval tvTimeout;

    fd_set readfds;

    socklen_t CliAddrLen;
    struct sockaddr_in saClientAddr;
    

    memset(&myAddr, 0, sizeof(struct sockaddr_in));

    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(ANODE_LPORT);
    myAddr.sin_addr.s_addr = INADDR_ANY;

    // create a socket
    if( (iListenSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
    {
        logerr("fStartClientListen(): socket()");
        goto error_return;
    }

    // set it to reuse address
    if( setsockopt(iListenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 )
        logwarn("fStartClientListen(): setsockopt() (%s)\n", strerror(errno));

    // bind it
    if( bind(iListenSocket, (struct sockaddr*)&myAddr, sizeof(struct sockaddr_in)) < 0 )
    {
        logerr("fStartClientListen(): bind()");
        goto error_return;
    }

    // set it as listen socket
    if( listen(iListenSocket, MAX_BACKLOG) < 0 )
    {
        logerr("fStartClientListen(): listen()");
        goto error_return;
    }
    
    // wait for client
    loginfo("fStartClientListen() started: Listening on socket %d at port %d", iListenSocket, 
            ANODE_LPORT);
    
    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(iListenSocket, &readfds);

        // set timeout as half a second
        tvTimeout.tv_sec = 0;
        tvTimeout.tv_usec = TIME_HALF_SEC_MICRO;

        if( select(iListenSocket+1, &readfds, NULL, NULL, &tvTimeout) == -1 )
        {
            logerr("fStartClientListen(): select() ");
            sleep(TIME_THREE_SEC);
            continue;
        }

        if( FD_ISSET(iListenSocket, &readfds) )
        {
            CliAddrLen = sizeof(struct sockaddr_in);

            // there is an incoming connection
            iNewSocket = accept(iListenSocket, (struct sockaddr*)&saClientAddr, &CliAddrLen);
            if(iNewSocket == -1)
            {
                logerr("fStartClientListen(): accept() ");
                sleep(TIME_ONE_SEC);
                continue;
            }
            break;

        }// if FD_SET
    }// while(1)
    
    memset(lg_szClientIP, 0, sizeof(lg_szClientIP));
    if( inet_ntop(AF_INET, &saClientAddr.sin_addr, lg_szClientIP, sizeof(lg_szClientIP)) == NULL )
    {
        logerr("inet_ntop() ");
        goto error_return;
    }
    
    loginfo("fStartClientListen(): New connection from %s\n", lg_szClientIP);
    
    close(iListenSocket);
    *piCliSocket = iNewSocket;
    return TRUE;
    
    error_return:
    if(iListenSocket != -1) { close(iListenSocket); iListenSocket  = -1; }
    *piCliSocket = -1;
    return FALSE;
    
}// fStartClientListen()


BOOL fCliCommHandler(int iCliSocket)
{
    ASSERT(iCliSocket > 0);
    ASSERT(g_pCliSharedKey && g_pbCliHMACKey);
    
    int state = CHS_HELLO_WAIT;
    BOOL fError = FALSE;
    BOOL fDone = FALSE;
    
    void *pvLC = NULL;
    int lcSize = 0;
    
    void *pvToFree = NULL;
    void *pvSkey = NULL;
    int nSkeySize = 0;
    
    
    lg_iClientSocket = iCliSocket;
    
    while(!fError && !fDone)
    {
        switch(state)
        {
            case CHS_HELLO_WAIT:
                if(!fWaitForHello())
                    fError = TRUE;
                state = CHS_HANDSHAKE;
                break;
                
            case CHS_HANDSHAKE:
                if(!fDoHandshake())
                    fError = TRUE;
                state = CHS_LOGIN_WAIT;
                break;

            case CHS_LOGIN_WAIT:
                if(!fWaitForLogin(&pvLC, &lcSize))
                    fError = TRUE;
                state = CHS_SERV_WAIT;
                break;
                
            case CHS_SERV_WAIT:
                if(!fWaitForServerApproval(&state, pvLC, lcSize,
                        &pvSkey, &nSkeySize, &pvToFree))
                    fError = TRUE;
                // state is set inside the function
                break;
                
            case CHS_CLI_LOGIN_FAILED:
                if(!fHandleClientLoginFail())
                    fError = TRUE;
                state = CHS_TERMINATE;
                break;
                
            case CHS_BEGIN_SESSION:
                if(!fBeginSession(pvSkey, nSkeySize, pvToFree))
                    fError = TRUE;
                state = CHS_DATA_FORWARD;
                break;
                
            case CHS_TERMINATE:
                if(!fTerminateConn())
                    fError = TRUE;
                fDone = TRUE;
                break;
                
            case CHS_DATA_FORWARD:
                if(!fDoDataForward())
                    fError = TRUE;
                state = CHS_TERMINATE;
                break;
                
            default: 
                logwarn("fCliCommHandler(): Invalid state %d!", state); 
                fError = TRUE; break;
            
        }// switch
    }// while
    
    fend:
    return;
}


static BOOL fWaitForHello()
{
    int iRetVal = 0;
    HELLO_PACKET helloPacket;


    loginfo("Waiting for hello from client...");
    while(1)
    {
        if(!fRecvBuffer(&iRetVal))
        {
            if(iRetVal == ERR_SOCKET_DOWN)
                loginfo("Client closed connection unexpectedly!");
            else
                loginfo("Read from client socket error (%s)", strerror(iRetVal));
            goto error_return;
        }
        
        memcpy(&helloPacket, lg_abSRBuffer, sizeof(helloPacket));
        if(helloPacket.mid == MSG_CA_HELLO && (strcmp(helloPacket.szMessage, "hello") == 0))
            break;
        
        loginfo("Invalid message ID/str from client: %d", helloPacket.mid);
        loginfo("Continuing wait for hello message...");
    }
    
    return TRUE;
    
    error_return:
    return FALSE;
    
}// fCliHandshake()


static BOOL fDoHandshake()
{
    int iRetVal = 0;
    
    HANDSHAKE handShake;
    uint32_t myNonce = 0;
    
    void *pvSendPacket = NULL;
    int nSendPacketSize = 0;
    
    int iMIDReply = 0;
    int nSizeReply = 0;
    HANDSHAKE *pCliResponse = NULL;
    
    
    // send challenge
    gcry_create_nonce(&myNonce, sizeof(uint32_t));
    logdbg("Sending challenge: %u", myNonce);
    
    handShake.u32Challenge = myNonce;
    handShake.u32Response = 0;
    
    if((pvSendPacket = pvConstructPacket(MSG_AC_CHALLENGE, &handShake, sizeof(handShake),
            g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES,
            g_pbCliHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nSendPacketSize)) == NULL )
    {
        logwarn("Unable to create handshake packet!");
        goto error_return;
    }
    
    vWriteToBuffer(pvSendPacket, nSendPacketSize);
    
    free(pvSendPacket); pvSendPacket = NULL;
    
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Client closed connection unexpectedly!");
        else
            loginfo("Failed to send handshake packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    // wait for response
    loginfo("Waiting for response to challenge");
    if(!fRecvBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Client closed socket unexpectedly!");
        else
            loginfo("Failed to receive handshake packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    // decrypt packet
    if(!fDeconstructPacket(g_pCliSharedKey->abKey, g_pbCliHMACKey, lg_abSRBuffer,
            sizeof(lg_abSRBuffer), &iMIDReply, &nSizeReply, (void**)&pCliResponse))
    {
        logwarn("Error in decrypting packet");
        goto error_return;
    }
    
    // verify response
    if(iMIDReply != MSG_CA_RESPCHAL)
    {
        loginfo("Invalid message ID received %d", iMIDReply);
        goto error_return;
    }
    
    if(pCliResponse->u32Response != myNonce+1)
    {
        loginfo("Invalid response to challenge received: %u", pCliResponse->u32Response);
        goto error_return;
    }
    
    loginfo("Client's response to challenge is correct");
    
    // reply back to client's challenge
    logdbg("Client's challenge: %u", pCliResponse->u32Challenge);
    handShake.u32Response = pCliResponse->u32Challenge+1;
    handShake.u32Challenge = 0;
    
    vFreePlainTextBuffer((void**)&pCliResponse);
    
    if((pvSendPacket = pvConstructPacket(MSG_AC_CHALRESP, &handShake, sizeof(HANDSHAKE),
            g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES, g_pbCliHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nSendPacketSize)) == NULL)
    {
        logwarn("Unable to create handshake response packet!");
        goto error_return;
    }
    
    vWriteToBuffer(pvSendPacket, nSendPacketSize);
    
    free(pvSendPacket); pvSendPacket = NULL;
    
    // send the response
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Client closed connection unexpectedly!");
        else
            loginfo("Failed to send handshake response packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    if(pvSendPacket) free(pvSendPacket);
    vFreePlainTextBuffer((void**)&pCliResponse);
    return FALSE;
}


static BOOL fWaitForLogin(void **ppvLoginCred, int *piLCSize)
{
    ASSERT(ppvLoginCred);
    
    int iRetVal = 0;
    
    int mid = 0;
    int msgSize = 0;
    void *pvMessage = NULL;
    
    
    // wait for packet
    loginfo("Waiting for login message from client...");
    
    while(1)
    {
        if(!fRecvBuffer(&iRetVal))
        {
            if(iRetVal == ERR_SOCKET_DOWN)
                loginfo("Client closed socket unexpectedly!");
            else
                loginfo("Failed to login message packet (%s)", strerror(iRetVal));
            goto error_return;
        }

        // decrypt packet
        if(!fDeconstructPacket(g_pCliSharedKey->abKey, g_pbCliHMACKey, lg_abSRBuffer,
                sizeof(lg_abSRBuffer), &mid, &msgSize, &pvMessage))
        {
            logwarn("Error in decrypting packet");
            goto error_return;
        }

        // verify response
        if(mid == MSG_CA_SERV_LOGIN)
            break;
        loginfo("Unexpected message with MID %d received", mid);
        loginfo("Will wait for login message...");
    }// while(1)
    
    if(msgSize <= CRYPT_HASH_SIZE_BYTES)
    {
        logwarn("Client's login cred message size invalid: %d", msgSize);
        goto error_return;
    }

    *ppvLoginCred = pvMessage+INET_ADDRSTRLEN;
    *piLCSize = msgSize-INET_ADDRSTRLEN;
    
    // check the server IP
    memcpy(lg_szServerIP, pvMessage, INET_ADDRSTRLEN);
    loginfo("Client wants to connect with %s", lg_szServerIP);
    loginfo("Client login_cred packet(%d): ", msgSize-INET_ADDRSTRLEN);
    vPrintBytes(*ppvLoginCred, msgSize-INET_ADDRSTRLEN);

    return TRUE;
    
    error_return:
    return FALSE;
}


/**
 * Sends the previously received client's login cred
 * to server and waits for accept/reject. Once server
 * has replied, if accept, then sets state = BEGIN_SESSION,
 * else, sets state = LOGIN_FAILED
 * 
 * @param pistate
 * @param pvLoginCred
 * @param lcSize
 * @return FALSE if an error occurs, TRUE otherwise
 */
static BOOL fWaitForServerApproval(int *pistate, void *pvLoginCred, int lcSize,
        void **ppvCliPacketOut, int *pnCliPacketSizeOut, void **ppvToFree)
{
    ASSERT(pistate && pvLoginCred);
    ASSERT(lcSize > CRYPT_HASH_SIZE_BYTES);
    ASSERT(ppvCliPacketOut);
    ASSERT(pnCliPacketSizeOut);
    
    BYTE *pbMsgContent = NULL;
    int nMsgSize = 0;
    
    void *pvSendPacket = NULL;
    int nSendPacketSize = 0;
    
    int mid = 0;
    int msgSize = 0;
    void *pvMessage = NULL;
    
    int iRetVal = 0;
    
    
    nMsgSize = INET_ADDRSTRLEN + lcSize;
    if((pbMsgContent = (BYTE*)malloc(nMsgSize)) == NULL)
    {
        logerr("fWaitForServerApproval(): malloc() ");
        goto error_return;
    }
    
    // send client's IP and login credentials
    memset(pbMsgContent, 0, nMsgSize);
    memcpy(pbMsgContent, lg_szClientIP, strlen(lg_szClientIP));
    memcpy(pbMsgContent+INET_ADDRSTRLEN, pvLoginCred, lcSize);
    
    // create a packet
    if((pvSendPacket = pvConstructPacket(MSG_AS_CLI_AUTH, pbMsgContent, nMsgSize,
            g_pServerSK->abKey, CRYPT_KEY_SIZE_BYTES,
            g_pbServerHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nSendPacketSize)) == NULL)
    {
        logwarn("Unable to create login cred packet!");
        goto error_return;
    }
    
    ASSERT(nSendPacketSize > nMsgSize);
    
    // send the response
    if(!fSendToServer(pvSendPacket, nSendPacketSize))
        goto error_return;
    
    free(pvSendPacket); pvSendPacket = NULL;
    free(pbMsgContent); pbMsgContent = NULL;
    
    // wait for server's accept/reject
    if(!fRecvFromServer(lg_abSRBuffer, sizeof(lg_abSRBuffer)))
        goto error_return;
    
    logdbg("Anode Packet: ");
    vPrintBytes(lg_abSRBuffer, sizeof(lg_abSRBuffer));
    
    if(!fDeconstructPacket(g_pServerSK->abKey, g_pbServerHMACKey, 
            lg_abSRBuffer, sizeof(lg_abSRBuffer),
            &mid, &msgSize, &pvMessage))
    {
        logwarn("Error in decrypting packet");
            goto error_return;
    }
    
    if(mid == MSG_SA_CLI_ACCEPT)
    {
        char *psz = (char*)pvMessage;
        *ppvCliPacketOut = pvMessage + INET_ADDRSTRLEN;
        *pnCliPacketSizeOut = msgSize - INET_ADDRSTRLEN;
        *ppvToFree = pvMessage;
        logdbg("Skey %p %d", *ppvCliPacketOut, *pnCliPacketSizeOut);
        *pistate = CHS_BEGIN_SESSION;
        loginfo("Server accepted client's (%s) login", psz);

        logdbg("Client packet(%d):", *pnCliPacketSizeOut);
        vPrintBytes(pvMessage + INET_ADDRSTRLEN, *pnCliPacketSizeOut);
    }
    else if(mid == MSG_SA_CLI_REJECT)
    {
        char *psz = (char*)pvMessage;
        *ppvCliPacketOut = NULL;
        *pnCliPacketSizeOut = 0;
        *pistate = CHS_CLI_LOGIN_FAILED;
        loginfo("Server rejected client's (%s) login", psz);
        
        vFreePlainTextBuffer(&pvMessage);
    }
    else
    {
        logwarn("Invalid message ID from server: %d", mid);
        *ppvCliPacketOut = NULL;
        *pnCliPacketSizeOut = 0;
        
        vFreePlainTextBuffer(&pvMessage);
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    vFreePlainTextBuffer(&pvMessage);
    if(pvSendPacket) free(pvSendPacket);
    return FALSE;

}


static BOOL fHandleClientLoginFail()
{
    fTerminateConn();
    fDoCleanUp();
    return TRUE;
    
    error_return:
    return FALSE;
}


static BOOL fBeginSession(void *pvCliPacket, int nCliPacketSize, void *pvToFree)
{
    ASSERT(pvCliPacket && nCliPacketSize > CRYPT_HASH_SIZE_BYTES);
    ASSERT(pvToFree);

    int iRetVal = 0;
    ATOKEN atoken;
    
    void *pvMessage = NULL;
    void *pvSendPacket = NULL;
    
    int nTotalMessageSize = 0;
    int nSendPacketSize = 0;
    
    // create access token
    if(!fCreateAccessToken(lg_szClientIP, lg_szServerIP, &atoken))
    {
        logwarn("Unable to create access token!");
        goto error_return;
    }
    
    // create session key
    if(!fSecureAlloc(CRYPT_KEY_SIZE_BYTES, (void**)&g_pbCliSessionKey))
    { logwarn("securealloc() error for session key"); goto error_return; }
    
    gcry_create_nonce((void*)g_pbCliSessionKey, CRYPT_KEY_SIZE_BYTES);
    
    // generate session HMAC key
    if((g_pbCliSessionHMACKey = pbGenHMACKey(g_pbCliSessionKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    {
        logwarn("Could not generate session HMAC key!");
        goto error_return;
    }
    
    logdbg("Client session key: ");
    vPrintBytes(g_pbCliSessionKey, CRYPT_KEY_SIZE_BYTES);
    logdbg("Client session HMAC key: ");
    vPrintBytes(g_pbCliSessionHMACKey, CRYPT_KEY_SIZE_BYTES);
    
    // create a packet: MSG_AC_SESS_EST + akey + atoken + servMsg
    nTotalMessageSize = CRYPT_KEY_SIZE_BYTES + sizeof(atoken) + nCliPacketSize;
    if((pvMessage = malloc(nTotalMessageSize)) == NULL)
    { logerr("fBeginSession(): malloc() "); goto error_return; }
    
    memcpy(pvMessage, g_pbCliSessionKey, CRYPT_KEY_SIZE_BYTES);
    memcpy(pvMessage+CRYPT_KEY_SIZE_BYTES, &atoken, sizeof(atoken));
    memcpy(pvMessage+CRYPT_KEY_SIZE_BYTES+sizeof(atoken), pvCliPacket, nCliPacketSize);

    if((pvSendPacket = pvConstructPacket(MSG_AC_SESS_EST, pvMessage, nTotalMessageSize,
            g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES,
            g_pbCliHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nSendPacketSize)) == NULL )
    {
        logwarn("Unable to create atoken packet!");
        goto error_return;
    }
    
    vWriteToBuffer(pvSendPacket, nSendPacketSize);
    
    free(pvMessage); pvMessage = NULL;
    free(pvSendPacket); pvSendPacket = NULL;
    vFreePlainTextBuffer(&pvToFree);
    
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Client closed connection unexpectedly!");
        else
            loginfo("Failed to send atoken packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    return FALSE;
}


static BOOL fDoDataForward()
{
    int iRetVal = 0;
    void *pvOuterPacket = NULL;
    int nOuterPacketSize = 0;
    
    int mid, msgSize;
    void *pvInnerPacket = NULL;
    
    while(1)
    {
        loginfo("Waiting for data from client");
        if(!fRecvBuffer(&iRetVal))
        {
            if(iRetVal == ERR_SOCKET_DOWN)
                loginfo("Client closed connection unexpectedly!");
            else
                loginfo("Failed to receive data packet (%s)", strerror(iRetVal));
            goto error_return;
        }
        
        if(!fDeconstructPacket(g_pbCliSessionKey, g_pbCliSessionHMACKey, 
                lg_abSRBuffer, sizeof(lg_abSRBuffer), 
                &mid, &msgSize, &pvInnerPacket))
        {
            logwarn("Failed to deconstruct outer packet from client");
            continue;
        }
        
        if(mid != MSG_CA_SERV_DATA)
        {
            logwarn("Invalid msg from client %d", mid);
            vFreePlainTextBuffer(&pvInnerPacket);
            continue;
        }
        
        // construct server packet and send
        if(!fConstSendServerPacket(lg_szClientIP, MSG_AS_CLI_REQ, 
                pvInnerPacket+INET_ADDRSTRLEN, msgSize-INET_ADDRSTRLEN))
        {
            logwarn("Could not forward request to server");
            vFreePlainTextBuffer(&pvInnerPacket);
            continue;
        }
        
        vFreePlainTextBuffer(&pvInnerPacket);
        
        // wait for reply from server
        if(!fRecvFromServer(lg_abSRBuffer, sizeof(lg_abSRBuffer)))
            goto error_return;
        
        // deconstruct it
        if(!fDeconstructPacket(g_pServerSK->abKey, g_pbServerHMACKey, 
                lg_abSRBuffer, sizeof(lg_abSRBuffer), 
                &mid, &msgSize, &pvInnerPacket))
        {
            logwarn("Failed to deconstruct outer packet from server");
            continue;
        }
        
        if(mid != MSG_SA_CLI_DATA)
        {
            logwarn("Invalid msg from server %d", mid);
            vFreePlainTextBuffer(&pvInnerPacket);
            continue;
        }
        
        // construct server packet and send
        if(!fConstSendClientPacket(MSG_AC_SERV_DATA, pvInnerPacket+INET_ADDRSTRLEN, msgSize-INET_ADDRSTRLEN))
        {
            logwarn("Could not forward serv data to client");
            continue;
        }
        
        vFreePlainTextBuffer(&pvInnerPacket);
    }
    
    return TRUE;
    
    error_return:
    return FALSE;
}


static BOOL fTerminateConn()
{
    close(lg_iClientSocket);
    lg_iClientSocket = -1;
    return TRUE;
    
    error_return:
    return FALSE;
}


static BOOL fDoCleanUp()
{
    
    error_return:
    return FALSE;
}


static void vWriteToBuffer(void *pvInput, int nInputSize)
{
    ASSERT(pvInput && nInputSize <= SR_BUFSIZE);
    
    memset(lg_abSRBuffer, 0, sizeof(lg_abSRBuffer));
    memcpy(lg_abSRBuffer, pvInput, nInputSize);
}


static BOOL fSendBuffer(int *piError)
{
    return PE_fSendPacket(lg_iClientSocket, lg_abSRBuffer, sizeof(lg_abSRBuffer),
            piError);
}


static BOOL fRecvBuffer(int *piError)
{
    memset(lg_abSRBuffer, 0, sizeof(lg_abSRBuffer));
    return PE_fRecvPacket(lg_iClientSocket, lg_abSRBuffer, sizeof(lg_abSRBuffer),
            piError);    
}


static void vFreePlainTextBuffer(void **pvMessageContents)
{
    if(pvMessageContents && *pvMessageContents)
        free((*pvMessageContents) - sizeof(int) - sizeof(int));
}


BOOL fCreateAccessToken(const char *pszClientIP, const char *pszServerIP,
        ATOKEN *pATokenOut)
{
    ASSERT(pszClientIP && pszServerIP);
    
    int nSize;
    
    BYTE *pbToBeHashed = NULL;
    
    memset(pATokenOut, 0, sizeof(ATOKEN));
    
    int cliLen = strlen(pszClientIP);
    int serLen = strlen(pszServerIP);
    
    ASSERT(cliLen > 0 && cliLen <= INET_ADDRSTRLEN);
    ASSERT(serLen > 0 && serLen <= INET_ADDRSTRLEN);
    
    if(gettimeofday(&pATokenOut->tvExpiry, NULL) == -1)
    {
        logerr("gettimeofday() ");
        return FALSE;
    }
    pATokenOut->tvExpiry.tv_sec = pATokenOut->tvExpiry.tv_sec + SECS_PER_DAY;
    pATokenOut->tvExpiry.tv_usec = 0;
    
    loginfo("Accesstoken expires %s", ctime(&pATokenOut->tvExpiry.tv_sec));
    
    nSize = cliLen + serLen + sizeof(struct timeval);
    if((pbToBeHashed = (BYTE*)malloc(nSize)) == NULL)
    {
        logerr("malloc() ");
        return FALSE;
    }
    
    memcpy(pbToBeHashed, pszClientIP, cliLen);
    memcpy(pbToBeHashed+cliLen, pszServerIP, serLen);
    memcpy(pbToBeHashed+cliLen+serLen, &pATokenOut->tvExpiry, sizeof(struct timeval));
    
    if(!fGetHMAC(g_pbANSecretKey, CRYPT_KEY_SIZE_BYTES,
            pbToBeHashed, nSize, 
            pATokenOut->abHmacCSIPTime, CRYPT_HASH_SIZE_BYTES,
            NULL))
    {
        logwarn("Unable to generate hash");
        free(pbToBeHashed);
        return FALSE;
    }
    
    return TRUE;
            
}// pCreateAccessToken()


BOOL fConstSendServerPacket(const char *pszClientIP, int mid, void *pvCliPacket, int nCliPacketSize)
{
    ASSERT(pszClientIP);
    ASSERT(nCliPacketSize == 0 || nCliPacketSize > CRYPT_HASH_SIZE_BYTES);
    
    int iRetVal = 0;
    void *pv = NULL;
    void *pvServerPacket = NULL;
    int nMsgSize, nServerPacketSize;
    
    
    nMsgSize = INET_ADDRSTRLEN + nCliPacketSize;
    if((pv = malloc(nMsgSize)) == NULL)
    {
        logerr("fConstSendAnodePacket(): malloc() ");
        return FALSE;
    }
    
    memcpy(pv, pszClientIP, INET_ADDRSTRLEN);
    if(pvCliPacket)
        memcpy(pv+INET_ADDRSTRLEN, pvCliPacket, nCliPacketSize);
    
    if((pvServerPacket = pvConstructPacket(mid, pv, nMsgSize, 
            g_pServerSK->abKey, CRYPT_KEY_SIZE_BYTES,
            g_pbServerHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nServerPacketSize)) == NULL)
    {
        logwarn("fConstSendAnodePacket(): Could not create packet");
        goto error_return;
    }
    if(!fSendToServer(pvServerPacket, nServerPacketSize))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Server closed socket unexpectedly!");
        else
            loginfo("Failed to send data packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    free(pv);
    free(pvServerPacket);
    return TRUE;
    
    error_return:
    if(pv) free(pv);
    if(pvServerPacket) free(pvServerPacket);
    return FALSE;
}


BOOL fConstSendClientPacket(int mid, void *pvServPacket, int nServPacketSize)
{
    ASSERT(nServPacketSize == 0 || nServPacketSize > CRYPT_HASH_SIZE_BYTES);
    
    int iRetVal = 0;
    void *pvClientPacket = NULL;
    int nClientPacketSize;


    if((pvClientPacket = pvConstructPacket(mid, pvServPacket, nServPacketSize, 
            g_pbCliSessionKey, CRYPT_KEY_SIZE_BYTES,
            g_pbCliSessionHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nClientPacketSize)) == NULL)
    {
        logwarn("fConstSendClientPacket(): Could not create packet");
        goto error_return;
    }
    
    vWriteToBuffer(pvClientPacket, nClientPacketSize);
    free(pvClientPacket); pvClientPacket = NULL;
    
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Client closed socket unexpectedly!");
        else
            loginfo("Failed to send data packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    if(pvClientPacket) free(pvClientPacket);
    return FALSE;
}
