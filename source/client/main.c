/* 
 * File:   main.c
 * Author: charanraj
 *
 * Created on April 26, 2013, 7:48 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <sys/time.h>

#include "../common/assert.h"
#include "../common/defs.h"
#include "../common/packet.h"
#include "../common/helpers.h"

#define OP_TYPE_ENC     1
#define OP_TYPE_DEC     2

int sock;

struct sockaddr_in accessaddr;
int rtnval;
int accessport;

LOGIN_CRED login;

int iRetVal = 0;

void *pvSendPacket = NULL;
int nSendPacketSize = 0;
int iMIDReply = 0;
int nSizeReply = 0;
HANDSHAKE *pAccResponse = NULL;


SHARED_KEY *g_pCliAnodeSharedKey;   // to store client-accessnode shared keys
BYTE *g_pbCliAnodeHMACKey;          // hmac key for client-server

SHARED_KEY  *g_pCliServerSharedKey;   // to store client-accessnode shared keys
BYTE *g_pbCliServerHMACKey;           // hmac key for client: hash(cli shared key)

BYTE *pbAKey;
BYTE *pbSKey;
BYTE *pbAHMACKey;
BYTE *pbSHMACKey;
ATOKEN *pAToken;

static BYTE lg_abSRBuffer[SR_BUFSIZE];


// File-local functions
BOOL fDoLoadGenKeys();
int socket_connection(int accessport, char* accessIP);
BOOL doHandshake();
BOOL sendLogin(char* usr, char* pwd, char* ServerIP);
BOOL receiveKey();
BOOL fStartService(const char *pszServerIP);
char *pszBase64Op(char *pszInput, int nInputSize, int opType, const char *pszServerIP);

static void vWriteToBuffer(void *pvInput, int nInputSize);
static BOOL fSendBuffer(int *piError);
static BOOL fRecvBuffer(int *piError);
static void vFreePlainTextBuffer(void **pvMessageContents);



int main(int argc, char *argv[]) {
    char *accessIP = NULL;
    char *serverIP = NULL;
    char usr[MAX_USERNAME+1];
    char pwd[MAX_PASSWD+1];
    
    if (argc != 3) {
        printf("usage: %s <access_node_IP> <server_IP>\n", argv[0]);
        return 1;
    }
    
    accessIP = argv[1];
    serverIP = argv[2];
    
    // load shared keys
    if(!fDoLoadGenKeys())
        return 1;
    
#ifdef _DEBUG
    printf("Anode Shared key: ");
    vPrintBytes(g_pCliAnodeSharedKey->abKey, CRYPT_KEY_SIZE_BYTES);
    printf("Anode HMAC key  : ");
    vPrintBytes(g_pbCliAnodeHMACKey, CRYPT_KEY_SIZE_BYTES);
    
    printf("Server Shared key: ");
    vPrintBytes(g_pCliServerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES);
    printf("Server HMAC key  : ");
    vPrintBytes(g_pbCliServerHMACKey, CRYPT_KEY_SIZE_BYTES);
#endif
    
    loginfo("%s %d %s",accessIP, accessport, serverIP);
    if(socket_connection(ANODE_LPORT, accessIP) < 0)
    {
        printf("Could not connect to access node!\n");
        return 1;
    }
    if(!doHandshake())
    {
        loginfo("Handshake with anode unsuccessful!");
        goto fend;
    }
        
    loginfo("Connected to anode...");
    printf("Username: ");
    scanf("%s", usr);
    printf("Password: ");
    scanf("%s", pwd);
    sendLogin(usr, pwd, serverIP);
    receiveKey();
    fStartService(serverIP);

    fend:
    if(sock != -1) close(sock);
    return 0;

}// main()


BOOL fDoLoadGenKeys()
{   
    // first, load the shared keys: anode-client key
    if(!fLoadSharedKeyFile(CA_SK_FILE, &g_pCliAnodeSharedKey))
    {
        logwarn("Could not load shared key file!");
        goto error_return;
    }
    
    // generate HMAC key
    if((g_pbCliAnodeHMACKey = pbGenHMACKey(g_pCliAnodeSharedKey->abKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    {
        logwarn("Could not generate HMAC key!");
        goto error_return;
    }
    
    // client-server
    if(!fLoadSharedKeyFile(CS_SK_FILE, &g_pCliServerSharedKey))
    {
        logwarn("Could not load shared key file!");
        goto error_return;
    }
    
    // generate HMAC key
    if((g_pbCliServerHMACKey = pbGenHMACKey(g_pCliServerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    {
        logwarn("Could not generate HMAC key!");
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    if(g_pCliServerSharedKey) vSecureFree(g_pCliServerSharedKey);
    if(g_pbCliServerHMACKey) vSecureFree(g_pbCliServerHMACKey);
    
    return FALSE;

}// fLoadSharedKeys()



int socket_connection(int accessport, char* accessIP)
{
    //printf("%d%s\n",accessport,accessIP);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
    {
        printf("error in socket");
        return -1;
    }
    
    memset(&accessaddr, 0, sizeof (accessaddr));
    accessaddr.sin_family = AF_INET;
    rtnval = inet_pton(AF_INET, accessIP, &accessaddr.sin_addr);
    if (rtnval == 0)
    {
        printf("inet_pton(): Not a valid address\n");
        close(sock);
        sock = -1;
        return -1;
    }
    else if (rtnval < 0)
    {
        printf("inet_pton() failed (%s)\n", strerror(errno));
        close(sock);
        sock = -1;
        return -1;
    }
    accessaddr.sin_port = htons(accessport);
    
    if (connect(sock, (struct sockaddr*) &accessaddr, sizeof (accessaddr)) < 0) 
    {
        printf("Could not connect to access node %s\n", accessIP);
        close(sock);
        sock = -1;
        return -1;
    }
    
    return 0;
    
}// socket_connection()


BOOL doHandshake()
{
    HELLO_PACKET hellomsg;
    HANDSHAKE handshake;
    HANDSHAKE *pAccessResponse = NULL;
    uint32_t myNonce = 0;
    uint32_t challengenonce = 0;
    
    
    hellomsg.mid=MSG_CA_HELLO;
    strcpy(hellomsg.szMessage, "hello");
    
    vWriteToBuffer(&hellomsg, sizeof(hellomsg));   

     if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed connection unexpectedly!");
        else
            loginfo("Failed to send handshake response packet (%s)", strerror(iRetVal));
        return FALSE;
    }
    
    loginfo("Waiting for response to hello");
    if(!fRecvBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed socket unexpectedly!");
        else
            loginfo("Failed to receive handshake packet (%s)", strerror(iRetVal));
        return FALSE;
    }
    
    if(!fDeconstructPacket(g_pCliAnodeSharedKey->abKey, g_pbCliAnodeHMACKey, lg_abSRBuffer,
            sizeof(lg_abSRBuffer), &iMIDReply, &nSizeReply, (void**)&pAccessResponse))
    {
        logwarn("Error in decrypting packet");
        return FALSE;
    }
    
    if(iMIDReply != MSG_AC_CHALLENGE)
    {
        loginfo("Invalid message ID received %d", iMIDReply);
        goto error_return;
    }
    challengenonce = pAccessResponse->u32Challenge;
    gcry_create_nonce(&myNonce, sizeof(uint32_t));
    logdbg("Sending challenge: %u", myNonce);
    
    handshake.u32Challenge = myNonce;
    handshake.u32Response = challengenonce+1;
    
    if((pvSendPacket = pvConstructPacket(MSG_CA_RESPCHAL, &handshake, sizeof(handshake),
            g_pCliAnodeSharedKey->abKey, CRYPT_KEY_SIZE_BYTES,
            g_pbCliAnodeHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nSendPacketSize)) == NULL )
    {
        logwarn("Unable to create handshake packet!");
        goto error_return;
    }
    
    vWriteToBuffer(pvSendPacket, nSendPacketSize);
    free(pvSendPacket); pvSendPacket = NULL;
    
    vFreePlainTextBuffer((void**)&pAccessResponse);
    
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed connection unexpectedly!");
        else
            loginfo("Failed to send handshake packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    loginfo("Waiting for response to challenge");
    if(!fRecvBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed socket unexpectedly!");
        else
            loginfo("Failed to receive handshake packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    if(!fDeconstructPacket(g_pCliAnodeSharedKey->abKey, g_pbCliAnodeHMACKey, lg_abSRBuffer,
            sizeof(lg_abSRBuffer), &iMIDReply, &nSizeReply, (void**)&pAccessResponse))
    {
        logwarn("Error in decrypting packet");
        goto error_return;
    }
    if(iMIDReply != MSG_AC_CHALRESP)
    {
        loginfo("Invalid message ID received %d", iMIDReply);
        goto error_return;
    }
    if(pAccessResponse->u32Response != myNonce+1)
    {
        loginfo("Invalid response to challenge received: %u", pAccessResponse->u32Response);
        goto error_return;
    }
    
    vFreePlainTextBuffer((void**)&pAccessResponse);
    return TRUE;
    
    error_return:
    vFreePlainTextBuffer((void**)&pAccessResponse);
    return FALSE;
}


BOOL sendLogin(char* usr, char* pwd, char* ServerIP)
{   
    void* packet1 = NULL;
    char* bufferptr = NULL;
    
    
    strcpy(login.szUsername, usr);
    strcpy(login.szPassphrase, pwd);
    packet1 = pvConstructPacket(MSG_CS_LOGIN, &login, sizeof(login),
                g_pCliServerSharedKey->abKey, CRYPT_KEY_SIZE_BYTES,
                g_pbCliServerHMACKey, CRYPT_KEY_SIZE_BYTES,
                &nSendPacketSize);
    
    if((bufferptr=(char*)malloc(nSendPacketSize+INET_ADDRSTRLEN)) == NULL)
    {
        logerr("send login malloc() ");
        goto error_return;
    }
    
    memset(bufferptr, 0, nSendPacketSize+INET_ADDRSTRLEN);
    strcpy(bufferptr, ServerIP);
    memcpy(bufferptr+INET_ADDRSTRLEN, packet1, nSendPacketSize);
    
    free(packet1);
    
    if((pvSendPacket = pvConstructPacket(MSG_CA_SERV_LOGIN, 
            bufferptr, nSendPacketSize+INET_ADDRSTRLEN,
            g_pCliAnodeSharedKey->abKey, CRYPT_KEY_SIZE_BYTES,
            g_pbCliAnodeHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nSendPacketSize)) == NULL )
    {
        logwarn("Unable to create handshake packet!");
        goto error_return;
    }
    
    free(bufferptr); bufferptr = NULL;
    
    vWriteToBuffer(pvSendPacket, nSendPacketSize);
    free(pvSendPacket); pvSendPacket = NULL;
    
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed connection unexpectedly!");
        else
            loginfo("Failed to send login credentials (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    if(packet1) free(packet1);
    if(bufferptr) free(bufferptr);
    return FALSE;
}


BOOL receiveKey()
{   
    void* pAccessSession;
    BYTE* serverAccessToken;
    
    BOOL fAllocSuccess = TRUE;
    
    
    loginfo("Waiting for access token from anode");
    if(!fRecvBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed socket unexpectedly!");
        else
            loginfo("Failed to receive handshake packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    if(!fDeconstructPacket(g_pCliAnodeSharedKey->abKey, g_pbCliAnodeHMACKey, lg_abSRBuffer,
            sizeof(lg_abSRBuffer), &iMIDReply, &nSizeReply, (void**)&pAccessSession))
    {
        logwarn("Error in decrypting packet");
        goto error_return;
    }
    if(iMIDReply != MSG_AC_SESS_EST)
    {
        loginfo("Invalid message ID received %d", iMIDReply);
        goto error_return;
    }
    
    fAllocSuccess &= fSecureAlloc(CRYPT_KEY_SIZE_BYTES, (void**)&pbAKey);
    fAllocSuccess &= fSecureAlloc(CRYPT_KEY_SIZE_BYTES, (void**)&pbSKey);
    fAllocSuccess &= fSecureAlloc(sizeof(ATOKEN), (void**)&pAToken);
    if(!fAllocSuccess)
    {
        logwarn("receiveKey(): fSecureAlloc() ");
        goto error_return;
    }
    
    memcpy(pbAKey, pAccessSession, CRYPT_KEY_SIZE_BYTES);
    memcpy(pAToken, pAccessSession+CRYPT_KEY_SIZE_BYTES, nSizeReply-CRYPT_KEY_SIZE_BYTES);
    
     if(!fDeconstructPacket(g_pCliServerSharedKey->abKey, g_pbCliServerHMACKey,
             pAccessSession+CRYPT_KEY_SIZE_BYTES+sizeof(ATOKEN),
             nSizeReply-CRYPT_KEY_SIZE_BYTES-sizeof(ATOKEN), 
             &iMIDReply, &nSizeReply, (void**)&serverAccessToken))
    {
        logwarn("Error in decrypting skey packet");
        goto error_return;
    }
    if(iMIDReply != MSG_SC_SESSION_KEY)
    {
        loginfo("Invalid message ID received %d", iMIDReply);
        goto error_return;
    }
    
    memcpy(pbSKey, serverAccessToken, CRYPT_KEY_SIZE_BYTES);
    
    // create session HMAC keys
    if((pbAHMACKey = pbGenHMACKey(pbAKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    {
        logwarn("Could not create session hmac akey");
        goto error_return;
    }
    
    if((pbSHMACKey = pbGenHMACKey(pbSKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    {
        logwarn("Could not create session hmac akey");
        goto error_return;
    }
    
    
    vFreePlainTextBuffer(&pAccessSession);
    vFreePlainTextBuffer((void**)&serverAccessToken);
    
#ifdef _DEBUG
    
    printf("AKey: ");
    vPrintBytes(pbAKey, CRYPT_KEY_SIZE_BYTES);
    printf("AHMACKey: ");
    vPrintBytes(pbAHMACKey, CRYPT_KEY_SIZE_BYTES);
    printf("SKey: ");
    vPrintBytes(pbSKey, CRYPT_KEY_SIZE_BYTES);
    printf("SHMACKey: ");
    vPrintBytes(pbSHMACKey, CRYPT_KEY_SIZE_BYTES);
    
#endif
    
    loginfo("Accesstoken expires %s", ctime(&pAToken->tvExpiry.tv_sec));
    vPrintBytes(pAToken->abHmacCSIPTime, CRYPT_HASH_SIZE_BYTES);
    
    return TRUE;
    
    error_return:
    if(pbAKey) vSecureFree(pbAKey);
    if(pbSKey) vSecureFree(pbSKey);
    if(pbAHMACKey) vSecureFree(pbAHMACKey);
    if(pbSHMACKey) vSecureFree(pbSHMACKey);
    if(pAToken) vSecureFree(pAToken);
    return FALSE;
}


BOOL fStartService(const char *pszServerIP)
{
    char chOpType;
    char szRequest[MAX_REQ_STR+1];
    char *pszOutput;
    
    loginfo("Logged in to server...");
    loginfo("Base64 encode/decode service available...");
    while(1)
    {
        printf("\nInput: ");
        memset(szRequest, 0, sizeof(szRequest));
        if(!fReadLineFromStdin(szRequest, sizeof(szRequest)))
        {
            logwarn("Could not read input!");
            continue;
        }
        printf("Encode/Decode/Quit? (e/c/q) ");
        scanf("%c", &chOpType);
        logdbg("Querying \"%s\"...", szRequest);
        if(tolower(chOpType) == 'q')
        {}
        else if(tolower(chOpType) == 'd')
            pszOutput = pszBase64Op(szRequest, sizeof(szRequest), OP_TYPE_DEC, pszServerIP);
        else
            pszOutput = pszBase64Op(szRequest, sizeof(szRequest), OP_TYPE_ENC, pszServerIP);
        if(!pszOutput)
            printf("Result: \"%s\"\n", "(null)");
        else
        {
            printf("Result: \"%s\"\n", pszOutput);
            vFreePlainTextBuffer((void**)&pszOutput);
        }
    }
    
    return TRUE;
}


char *pszBase64Op(char *pszInput, int nInputSize, int opType, const char *pszServerIP)
{
    ASSERT(pszInput && nInputSize > 0 && nInputSize <= MAX_REQ_STR+1);
    ASSERT(pszServerIP);
    
    int mid;
    void *pvInnerPacket = NULL;
    int nInnerPacketSize = 0;
    
    void* pvAnodeMsg = NULL;
    int anodeMsgSize = 0;
    
    void *pvOuterPacket = NULL;
    int nOuterPacketSize = 0;
    
    if(opType == OP_TYPE_ENC)
        mid = MSG_CS_ENCODE;
    else if(opType == OP_TYPE_DEC)
        mid = MSG_CS_DECODE;
    else
        return NULL;
    
    // send request
    if((pvInnerPacket = pvConstructPacket(mid, pszInput, nInputSize, 
            pbSKey, CRYPT_KEY_SIZE_BYTES,
            pbSHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nInnerPacketSize)) == NULL)
        return NULL;
    
    anodeMsgSize = INET_ADDRSTRLEN + nInnerPacketSize;
    if((pvAnodeMsg = malloc(anodeMsgSize)) == NULL)
    {
        logerr("send service req malloc() ");
        goto error_return;        
    }
    
    memset(pvAnodeMsg, 0, anodeMsgSize);
    strcpy(pvAnodeMsg, pszServerIP);
    memcpy(pvAnodeMsg+INET_ADDRSTRLEN, pvInnerPacket, nInnerPacketSize);
    
    free(pvInnerPacket); pvInnerPacket = NULL;
    
    if((pvOuterPacket = pvConstructPacket(MSG_CA_SERV_DATA, 
            pvAnodeMsg, anodeMsgSize,
            pbAKey, CRYPT_KEY_SIZE_BYTES,
            pbAHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nOuterPacketSize)) == NULL )
    {
        logwarn("Unable to create op service packet!");
        goto error_return;
    }
    
    vWriteToBuffer(pvOuterPacket, nOuterPacketSize);
    free(pvOuterPacket); pvOuterPacket = NULL;
    
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed connection unexpectedly!");
        else
            loginfo("Failed to send login credentials (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    // wait for reply
    loginfo("Waiting for service reply...");
    if(!fRecvBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed socket unexpectedly!");
        else
            loginfo("Failed to receive reply packet (%s)", strerror(iRetVal));
        goto error_return;
    }
    
    if(!fDeconstructPacket(pbAKey, pbAHMACKey, lg_abSRBuffer,
            sizeof(lg_abSRBuffer), &mid, &anodeMsgSize, (void**)&pvAnodeMsg))
    {
        logwarn("Error in decrypting packet");
        goto error_return;
    }
    
    if(mid != MSG_AC_SERV_DATA)
    {
        logwarn("Invalid mid %d received", mid);
        goto error_return;
    }
    
    // deconstruct inner packet
    if(!fDeconstructPacket(pbSKey, pbSHMACKey, pvAnodeMsg,
            anodeMsgSize, &mid, &nInnerPacketSize, (void**)&pvInnerPacket))
    {
        logwarn("Error in decrypting packet");
        goto error_return;
    }
    
    if(nInnerPacketSize <= 0 || nInnerPacketSize > MAX_REQ_STR+1)
    {
        logwarn("Invalid result string size");
        goto error_return;
    }
    
    vFreePlainTextBuffer(&pvAnodeMsg);
    return (char*)pvInnerPacket;
    
    error_return:
    if(pvInnerPacket) free(pvInnerPacket);
    if(pvAnodeMsg) free(pvAnodeMsg);
    return NULL;
}


static void vWriteToBuffer(void *pvInput, int nInputSize)
{
    ASSERT(pvInput && nInputSize <= SR_BUFSIZE);
    
    memset(lg_abSRBuffer, 0, sizeof(lg_abSRBuffer));
    memcpy(lg_abSRBuffer, pvInput, nInputSize);
}


static BOOL fSendBuffer(int *piError)
{
    return PE_fSendPacket(sock, lg_abSRBuffer, sizeof(lg_abSRBuffer),
            piError);
}


static BOOL fRecvBuffer(int *piError)
{
    memset(lg_abSRBuffer, 0, sizeof(lg_abSRBuffer));
    return PE_fRecvPacket(sock, lg_abSRBuffer, sizeof(lg_abSRBuffer),
            piError);    
}

static void vFreePlainTextBuffer(void **pvMessageContents)
{
    if(pvMessageContents && *pvMessageContents)
        free((*pvMessageContents) - sizeof(int) - sizeof(int));
}
