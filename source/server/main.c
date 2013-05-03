
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
#include "keys.h"

#define USERS_FILE  "../etc/passwd.dat"
#define CS_SK_FILE  "../etc/cs_sharedkey.dat"


SHARED_KEY  *g_pANSerSharedKey;    // to store acessnode-server server shared keys
BYTE *g_pbANSerHMACKey; 		//hmac key for accessnode: hash(ANSer shared key)

SHARED_KEY  *g_pCliSerSharedKey;    // to store client server shared keys
BYTE *g_pbCliSerHMACKey;            // hmac key for client: hash(CliSer shared key)

int listener; // listening socket descriptor
int newfd; // newly accept()ed socket descriptor
struct sockaddr_in remoteaddr; // client address	
socklen_t addrlen;
char buf[512];
int nbytes; // buffer for client data
char *AccessIP = NULL;
int yes = 1;
int i, j, rv;
char sendbuffer[SR_BUFSIZE], receivebuffer[SR_BUFSIZE];
struct sockaddr_in servaddr;
void *pASMsg;
void *pCSMsg;
static BYTE lg_abSRBuffer[SR_BUFSIZE];


// Functions
static BOOL fDoLoadANodeKey();
static BOOL fDoLoadCliSharedKey(const char *pszFilepath);
int socket_connection(int PORT);
void communication();


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
    while (1) {
        printf("Enter the message");
        scanf("%s", sendbuffer);
        PE_fSendPacket(newfd, lg_abSRBuffer, SR_BUFSIZE , 0);

        PE_fRecvPacket(newfd, lg_abSRBuffer, SR_BUFSIZE , 0);

        printf("MESSAGE RECEIVED:%s", lg_abSRBuffer);
    }
    //switch();
    if(!fDeconstructPacket(g_pANSerSharedKey->abKey, g_pbANSerHMACKey, 
            lg_abSRBuffer, sizeof(lg_abSRBuffer), 
            &iMIDASMsg, &nSizeASMsg, (void**)&pASMsg))
    {
        logwarn("Error in decrypting packet");
        exit(1);
    }
   if(!fDeconstructPacket(g_pCliSerSharedKey->abKey, g_pbCliSerHMACKey,
           pASMsg, nSizeASMsg, 
           &iMIDCSMsg, &nSizeCSMsg, (void**)&pCSMsg))
    {
        logwarn("Error in decrypting packet");
        exit(1);
    }
   
        
}// communication()
