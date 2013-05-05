
#include <netinet/in.h>


#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>

#include "../common/defs.h"
#include "../common/packet.h"
#include "../common/packet_exchange.h"
#include "../common/helpers.h"
#include "../common/base64/base64.h"

#include "keys.h"


#define USERS_FILE  "../etc/passwd.dat"
#define CS_SK_FILE  "../etc/cs_sharedkey.dat"


SHARED_KEY  *g_pANSerSharedKey;    // to store acessnode-server server shared keys
BYTE *g_pbANSerHMACKey; 		//hmac key for accessnode: hash(ANSer shared key)

SHARED_KEY  *g_pCliSerSharedKey;    // to store client server shared keys
BYTE *g_pbCliSerHMACKey;            // hmac key for client: hash(CliSer shared key)

BYTE *pbSKey;
BYTE *pbSHMACKey;


int listener; // listening socket descriptor
int newfd; // newly accept()ed socket descriptor
struct sockaddr_in remoteaddr; // client address	
socklen_t addrlen;
char *AccessIP = NULL;
struct sockaddr_in servaddr;

static BYTE lg_abSRBuffer[SR_BUFSIZE];

BOOL fClientLoggedIn = FALSE;
char clientIP[INET_ADDRSTRLEN];


// Functions
static BOOL fDoLoadANodeKey();
static BOOL fDoLoadCliSharedKey(const char *pszFilepath);
int socket_connection(int PORT);
void communication();
BOOL fAcceptClient(const char *pszClientIP);
BOOL fRejectClient(const char *pszClientIP);
BOOL fHandleCliRequest(int mid, int msgSize, void *pvMessage, 
        void **pvCliPacket, int *pnCliPacketSize);
BOOL fClientLogout();

BOOL fConstSendAnodePacket(const char *pszClientIP, int mid, 
        void *pvCliPacket, int nCliPacketSize);
static void vWriteToBuffer(void *pvInput, int nInputSize);
static BOOL fSendBuffer(int *piError);
static BOOL fRecvBuffer(int *piError);
static void vFreePlainTextBuffer(void **pvMessageContents);


/**
 * 
 * @param argc
 * @param argv
 * @return 
 */
int main(int argc, char *argv[]) {
    
    if (argc != 2) {
        printf("usage: %s <access_node_IP>\n", argv[0]);
        return 1;
    }

    AccessIP = argv[1];
    printf("%s\n", AccessIP);
    
    // load client username-password file
    if(!fLoadUsersFromFile(USERS_FILE))
    {
        logwarn("Could not load user passwd file");
        return 1;
    }

    // wait for connect from accessnode
    if(socket_connection(SERVR_LPORT) < 0)
    {
        loginfo("Failed to receive connect() from accessnode");
        return 1;
    }
    
    // load anode shared key
    if(!fDoLoadANodeKey())
        return 1;
    
    // load client shared key file
    if(!fDoLoadCliSharedKey(CS_SK_FILE))
        return 1;
    
#ifdef _DEBUG
    printf("Anode Shared key: ");
    vPrintBytes(g_pANSerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES);
    printf("Anode HMAC key  : ");
    vPrintBytes(g_pbANSerHMACKey, CRYPT_KEY_SIZE_BYTES);
    
    printf("Client Shared key: ");
    vPrintBytes(g_pCliSerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES);
    printf("Client HMAC key  : ");
    vPrintBytes(g_pbCliSerHMACKey, CRYPT_KEY_SIZE_BYTES);
#endif
    
    communication();
    
    return 0;
    
}// main()


static BOOL fDoLoadANodeKey()
{
    // shared key first
    if(!fLoadSharedKeyFile(AS_SK_FILE, &g_pANSerSharedKey))
    { logwarn("Could not load AS shared key file"); goto error_return; }
    
    // calculate hmac key from shared key
    if((g_pbANSerHMACKey = pbGenHMACKey(g_pANSerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    { logwarn("Could not generate server HMAC key"); goto error_return; }
    
    return TRUE;
    
    error_return:
    if(g_pANSerSharedKey) vSecureFree(g_pANSerSharedKey);
    if(g_pbANSerHMACKey) vSecureFree(g_pbANSerHMACKey);
    g_pANSerSharedKey = NULL;
    g_pbANSerHMACKey = NULL;
    return FALSE;
}


static BOOL fDoLoadCliSharedKey(const char *pszFilepath)
{      
    if(!fLoadSharedKeyFile(pszFilepath, &g_pCliSerSharedKey))
    { logwarn("Could not load CS shared key file"); goto error_return; }
    
    // generate HMAC keys for each
    if((g_pbCliSerHMACKey = pbGenHMACKey(g_pCliSerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    { logwarn("Could not generate client HMAC key"); goto error_return; }
    
    return TRUE;
    
    error_return:
    if(g_pCliSerSharedKey) vSecureFree(g_pCliSerSharedKey);
    if(g_pbCliSerHMACKey) vSecureFree(g_pbCliSerHMACKey);
    g_pCliSerSharedKey = NULL;
    g_pbCliSerHMACKey = NULL;
    return FALSE;

}// fLoadSharedKeys()


int socket_connection(int PORT) {
    
    int yes = 1;
    char remoteIP[INET_ADDRSTRLEN+1];
    
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0)
    {
        printf("socket() failed");
        return -1;
    }
    
    // set it to reuse address
    if( setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 )
    {
        logwarn("socket_connection(): setsockopt() failed %s\n", strerror(errno));
        // not a critical error
    }
    
    memset(&servaddr, 0, sizeof (servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
    if (bind(listener, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 0) {
        printf("bind failed");
        close(listener);
        return -1;
    }
    
    if (listen(listener, 10) == -1) {
        printf("listen() failed");
        close(listener);
        return -1;
    }
    
    printf("Waiting for connection from %s...\n", AccessIP);
    while(1)
    {
        addrlen = sizeof (remoteaddr);
        newfd = accept(listener, (struct sockaddr *) &remoteaddr, &addrlen);
        if (newfd == -1) {
            printf("Accept Failed (%s)\n", strerror(errno));
        } else {
            if(inet_ntop(AF_INET, &remoteaddr.sin_addr, remoteIP, sizeof(remoteIP)) == NULL)
            {
                logerr("inet_ntop() failed ");
                close(newfd); newfd = -1;
            }
            if(strcmp(remoteIP, AccessIP) != 0)
            {
                logwarn("Connection from unexpected IP address %s", remoteIP);
                close(newfd); newfd = -1;
            }
            printf("Accepting connection from access node at %s\n", remoteIP);
            break;
        }
    }
    
    return 0;
    
}// socket_connection()


void communication() {

    int iMIDASMsg = 0;
    int nSizeASMsg= 0;
    int iMIDCSMsg = 0;
    int nSizeCSMsg= 0;
    
    int iRetVal = 0;
    
    void *pASMsg = NULL;
    LOGIN_CRED *pCSMsg = NULL;

    
    while (1) {
        // wait for message from accessnode
        loginfo("Waiting for message from anode");
        if(!fRecvBuffer(&iRetVal))
        {
            if(iRetVal == ERR_SOCKET_DOWN)
                loginfo("Accessnode closed socket unexpectedly!");
            else
                loginfo("Failed to login message packet (%s)", strerror(iRetVal));
            break;
            //goto error_return;
        }
        else
        {
            loginfo("MESSAGE RECEIVED: ");
            
            // handle outer packet
            if(!fDeconstructPacket(g_pANSerSharedKey->abKey, g_pbANSerHMACKey, 
                    lg_abSRBuffer, sizeof(lg_abSRBuffer), 
                    &iMIDASMsg, &nSizeASMsg, (void**)&pASMsg))
            {
                logwarn("Error in decrypting outer packet");
                exit(1);
            }

            memcpy(clientIP, pASMsg, INET_ADDRSTRLEN);

            switch(iMIDASMsg)
            {
                case MSG_AS_CLI_AUTH:
                    // first deconstruct the inner packet
                    if(!fDeconstructPacket(g_pCliSerSharedKey->abKey, g_pbCliSerHMACKey,
                       pASMsg+INET_ADDRSTRLEN, nSizeASMsg-INET_ADDRSTRLEN, 
                       &iMIDCSMsg, &nSizeCSMsg, (void**)&pCSMsg))
                    {
                        logwarn("Error in decrypting inner packet login");
                        break;
                    }
                    
                    if((fVerifyUserGetKey(pCSMsg->szUsername, pCSMsg->szPassphrase))== TRUE)
                    {
                        loginfo("User \"%s\" authenticated", pCSMsg->szUsername);
                        if(!fAcceptClient(clientIP))
                            logwarn("Failed to accept user");
                        fClientLoggedIn = TRUE;
                    }
                    else
                    {
                        logwarn("User \"%s\" NOT authenticated", pCSMsg->szUsername);
                        fConstSendAnodePacket(clientIP, MSG_SA_CLI_REJECT, NULL, 0);
                    }
                    vFreePlainTextBuffer((void**)&pCSMsg);
                    break;

                case MSG_AS_CLI_REQ:
                {
                    void *pvCliPacket = NULL;
                    int nCliPacketSize = 0;
                    
                    // first deconstruct the inner packet
                    if(!fDeconstructPacket(pbSKey, pbSHMACKey,
                       pASMsg+INET_ADDRSTRLEN, nSizeASMsg-INET_ADDRSTRLEN, 
                       &iMIDCSMsg, &nSizeCSMsg, (void**)&pCSMsg))
                    {
                        logwarn("Error in decrypting inner packet");
                        exit(1);
                    }

                    if(fHandleCliRequest(iMIDCSMsg, nSizeCSMsg, pCSMsg, 
                            &pvCliPacket, &nCliPacketSize))
                    {
                        fConstSendAnodePacket(clientIP, MSG_SA_CLI_DATA, 
                                pvCliPacket, nCliPacketSize);
                        free(pvCliPacket); pvCliPacket = NULL;
                    }
                        
                    vFreePlainTextBuffer((void**)&pCSMsg);
                    break;
                }
                
                default:
                    logwarn("Invalid msgID %d from anode", iMIDASMsg);
                    break;

            }// switch ASmID
            
            vFreePlainTextBuffer(&pASMsg);
        
        }// if recv
    
    }// while(1)
    
    return;
        
}// communication()



BOOL fAcceptClient(const char *pszClientIP)
{   
    void *clientPacket = NULL;
    int nCliPacketSize = 0;
    
    
    if(!fSecureAlloc(CRYPT_KEY_SIZE_BYTES, (void**)&pbSKey))
    { logwarn("fAcceptClient(): Could not allocate memory"); return FALSE; }
    gcry_create_nonce(pbSKey, CRYPT_KEY_SIZE_BYTES);
    if((pbSHMACKey = pbGenHMACKey(pbSKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    {
        logwarn("Could not create hmac key");
        goto error_return;
    }

    logdbg("Client session key: ");
    vPrintBytes(pbSKey, CRYPT_KEY_SIZE_BYTES);
    logdbg("HMAC session key: ");
    vPrintBytes(pbSHMACKey, CRYPT_KEY_SIZE_BYTES);

    if((clientPacket = pvConstructPacket(MSG_SC_SESSION_KEY, pbSKey, CRYPT_KEY_SIZE_BYTES,
      g_pCliSerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES,
      g_pbCliSerHMACKey, CRYPT_KEY_SIZE_BYTES,
      &nCliPacketSize)) == NULL)
    {
        logwarn("fAcceptClient(): Unable to create client packet");
        goto error_return;
    }

    logdbg("Client Packet(%d): ", nCliPacketSize);
    vPrintBytes(clientPacket, nCliPacketSize);
    
    fConstSendAnodePacket(pszClientIP, MSG_SA_CLI_ACCEPT, clientPacket, nCliPacketSize);

    free(clientPacket); clientPacket = NULL;
    return TRUE;
 
    error_return:
    if(clientPacket) free(clientPacket);
    if(pbSKey) vSecureFree(pbSKey);
    if(pbSHMACKey) vSecureFree(pbSHMACKey);
    return FALSE;
}


BOOL fHandleCliRequest(int mid, int msgSize, void *pvMessage, 
        void **ppvCliPacket, int *pnCliPacketSize)
{   
    void *pvSendPacket = NULL;
    int nSendPacketSize = 0;
    
    BYTE *pbInput;
    int nInputLen;
    
    BYTE *pbOutput;
    int nOutputLen;
    
    char szOutput[MAX_REQ_STR+1];
    
    
    pbInput = (BYTE*)pvMessage;
    nInputLen = strlen(pbInput);
    if(nInputLen <= 0)
    {
        loginfo("Client input string length <= 0");
        return TRUE;
    }
    
    if(nInputLen > MAX_REQ_STR)
        nInputLen = MAX_REQ_STR;
    
    switch(mid)
    {
        case MSG_CS_ENCODE:
            pbOutput = base64(pbInput, nInputLen, &nOutputLen);
            break;
            
        case MSG_CS_DECODE:
            pbOutput = unbase64(pbInput, nInputLen, &nOutputLen);            
            break;
            
        case MSG_CS_LOGOUT:
            return fClientLogout();
    }
    
    if(pbOutput == NULL || nOutputLen <= 0 || nOutputLen > MAX_REQ_STR)
    {
        // fail message
        if((pvSendPacket = pvConstructPacket(MSG_SC_OP_FAIL, NULL, 0, 
                pbSKey, CRYPT_KEY_SIZE_BYTES,
                pbSHMACKey, CRYPT_KEY_SIZE_BYTES,
                &nSendPacketSize)) == NULL)
        {
            logwarn("Could not create op reply packet");
            goto error_return;
        }
    }
    else
    {
        memset(szOutput, 0, sizeof(szOutput));
        strcpy(szOutput, pbOutput);
        // success message
        if((pvSendPacket = pvConstructPacket(MSG_SC_OP_SUCCESS, szOutput, sizeof(szOutput), 
                pbSKey, CRYPT_KEY_SIZE_BYTES,
                pbSHMACKey, CRYPT_KEY_SIZE_BYTES,
                &nSendPacketSize)) == NULL)
        {
            logwarn("Could not create op reply packet");
            goto error_return;
        }
    }
    
    *ppvCliPacket = pvSendPacket;
    *pnCliPacketSize = nSendPacketSize;
    return TRUE;
    
    error_return:
    if(pvSendPacket) free(pvSendPacket);
    *ppvCliPacket = NULL;
    *pnCliPacketSize = 0;
    return FALSE;
    
}// fHandleCliRequest()


BOOL fClientLogout()
{
    loginfo("Client %s wants to logout", clientIP);
    if(!fConstSendAnodePacket(clientIP, MSG_SA_CLI_TERM, NULL, 0))
        return FALSE;
    loginfo("Sent TERM message to anode");
    memset(clientIP, 0, sizeof(clientIP));
    fClientLoggedIn = FALSE;
    if(pbSKey) vSecureFree(pbSKey);
    if(pbSHMACKey) vSecureFree(pbSHMACKey);
    pbSKey = pbSHMACKey = NULL;
    return TRUE;
    
}// fClientLogout()


BOOL fConstSendAnodePacket(const char *pszClientIP, int mid, void *pvCliPacket, int nCliPacketSize)
{
    ASSERT(pszClientIP);
    ASSERT(nCliPacketSize == 0 || nCliPacketSize > CRYPT_HASH_SIZE_BYTES);
    
    int iRetVal = 0;
    void *pv = NULL;
    void *pvAnodePacket = NULL;
    int nMsgSize, nAnodePacketSize;
    
    
    nMsgSize = INET_ADDRSTRLEN + nCliPacketSize;
    if((pv = malloc(nMsgSize)) == NULL)
    {
        logerr("fConstSendAnodePacket(): malloc() ");
        return FALSE;
    }
    
    memcpy(pv, pszClientIP, INET_ADDRSTRLEN);
    if(pvCliPacket)
        memcpy(pv+INET_ADDRSTRLEN, pvCliPacket, nCliPacketSize);
    
    if((pvAnodePacket = pvConstructPacket(mid, pv, nMsgSize, 
            g_pANSerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES,
            g_pbANSerHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nAnodePacketSize)) == NULL)
    {
        logwarn("fConstSendAnodePacket(): Could not create packet");
        goto error_return;
    }
    vWriteToBuffer(pvAnodePacket, nAnodePacketSize);
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Anode closed socket unexpectedly!");
        else
            loginfo("Failed to send message packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    free(pv);
    free(pvAnodePacket);
    return TRUE;
    
    error_return:
    if(pv) free(pv);
    if(pvAnodePacket) free(pvAnodePacket);
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
    return PE_fSendPacket(newfd, lg_abSRBuffer, sizeof(lg_abSRBuffer),
            piError);
}


static BOOL fRecvBuffer(int *piError)
{
    memset(lg_abSRBuffer, 0, sizeof(lg_abSRBuffer));
    return PE_fRecvPacket(newfd, lg_abSRBuffer, sizeof(lg_abSRBuffer),
            piError);
}


static void vFreePlainTextBuffer(void **pvMessageContents)
{
    if(pvMessageContents && *pvMessageContents)
        free((*pvMessageContents) - sizeof(int) - sizeof(int));
}
