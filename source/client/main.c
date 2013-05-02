/* 
 * File:   main.c
 * Author: charanraj
 *
 * Created on April 26, 2013, 7:48 PM
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netdb.h>
#include<arpa/inet.h>

#include "../common/assert.h"
#include "../common/defs.h"
#include "../common/packet.h"
#include "../common/helpers.h"

//void *Communicate(void *);
//void *Receive(void *);

int sock;
int choice;
char message[1024];
char reply[1024];
char usr[20];
char pwd[20];
char data[1024];
struct sockaddr_in accessaddr;
int rtnval;
int accessport;

HELLO_PACKET hellomsg;
HANDSHAKE handshake;
int iRetVal = 0;
HANDSHAKE handShake;
HANDSHAKE *pAccessResponse = NULL;
uint32_t myNonce = 0;
void *pvSendPacket = NULL;
SHARED_KEY  *g_pCliSharedKey;   // to store client-accessnode shared keys
BYTE *g_pbCliHMACKey;           // hmac key for client: hash(cli shared key)
int nSendPacketSize = 0;
int iMIDReply = 0;
int nSizeReply = 0;
HANDSHAKE *pAccResponse = NULL;
void *pvgen = NULL;

SHARED_KEY  *g_pCliSharedKey;    // to store client-accessnode shared keys
BYTE *g_pbCliHMACKey;            // hmac key for client: hash(cli shared key)

uint32_t challengenonce=0;
static int lg_iClientSocket;
static BYTE lg_abSRBuffer[SR_BUFSIZE];


// File-local functions
static void vWriteToBuffer(void *pvInput, int nInputSize);
static BOOL fSendBuffer(int *piError);
static BOOL fRecvBuffer(int *piError);

static BOOL fDoLoadGenKeys();
int socket_connection(int accessport, char* accessIP);
void doHandshake();



int main(int argc, char *argv[]) {
    char *accessIP = NULL;
    char *serverIP = NULL;
    
    
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
    printf("Shared key: ");
    vPrintBytes(g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES);
    printf("HMAC key  : ");
    vPrintBytes(g_pbCliHMACKey, CRYPT_KEY_SIZE_BYTES);
#endif
    
    //printf("%s%d%s",accessIP,accessport,serverIP);
    if(socket_connection(ANODE_LPORT, accessIP) < 0)
    {
        printf("Could not connect to access node!\n");
        return 1;
    }
    doHandshake();
    
    printf("USERNAME:");
    scanf("%s",usr);
    printf("PASSWORD:");
    scanf("%s",pwd);
    
    printf("what would you like to perform?\n"); 
    printf("1.Write into a file\n");
    printf("2.Read from a file\n");
    printf("3.Quit\n");
    scanf("%d",&choice);
    switch(choice)
    {
        case 1:
            printf("Enter the data to be written:\n");
            scanf("%s",data);
            break;
        case 2:
            printf("Retrieving data..");
            break;
        case 3:
            printf("Shutting Down..\n");
            printf("Good Bye!!");
            break;
        default:
            printf("Please enter the correct choice.");
    }
    
    //handshake(serverIP);
    /*sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        printf("error in socket");
    memset(&accessaddr, 0, sizeof (accessaddr));
    accessaddr.sin_family = AF_INET;
    rtnval = inet_pton(AF_INET, accessIP, &accessaddr.sin_addr);
    if (rtnval == 0)
        printf("Not a valid address");
    else if (rtnval < 0)
        printf("inet_pton() failed");
    accessaddr.sin_port = htons(accessport);
    if (connect(sock, (struct sockaddr*) &accessaddr, sizeof (accessaddr)) < 0) 
    {
        printf("Could not connect");
        return 1;
    }*/
   /* while (1) {
        char buf[512];
        int err;
        memset(buf, 0, sizeof (buf));
        printf("Enter the message");
        gets(buf);
        if (send(sock, buf, sizeof (buf), 0) < 0) {
            printf("Send Failed");
        }
        if (recv(sock, buf, sizeof (buf), 0) < 0);
        {
            printf("Received Failed %s", strerror(errno));
        }
        printf("MESSAGE RECEIVED:%s", buf);
    }*/

    fend:
    if(sock != -1) close(sock);
    return 0;

}// main()


static BOOL fDoLoadGenKeys()
{   
    // first, load the shared keys: anode-server key AND anode-client key
    
    if(!fLoadSharedKeyFile(FILE_AC_SK_BEGIN, &g_pCliSharedKey))
    {
        logwarn("Could not load shared key file!");
        return 1;
    }
    
    // generate HMAC key
    if((g_pbCliHMACKey = pbGenHMACKey(g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    {
        logwarn("Could not generate HMAC key!");
        return 1;
    }
    
    return TRUE;
    
    error_return:
    if(g_pCliSharedKey) vSecureFree(g_pCliSharedKey);
    if(g_pbCliHMACKey) vSecureFree(g_pbCliHMACKey);
    return FALSE;

}// fLoadSharedKeys()


/**
 * 
 */
/*void *Communicate(void *thread_arg)
{
        int echostringlen;
        ssize_t numbytes;
        int MAXSTRINGLENGTH = 500;
        struct sockaddr_storage fromAddr;
        int numbytesrecv;
        char buffer[MAXSTRINGLENGTH + 1];
        printf("Please enter a value :");
while(1)
        {

        scanf("%s",echostring);
        echostringlen=strlen(echostring);
        printf("In to the thread %s %d\n", echostring,echostringlen);
        numbytes=sendto(sock,echostring,echostringlen,0,(struct sockaddr*) &proxyaddr,sizeof(proxyaddr));
        if(numbytes<0)
                printf("send() failed");
        else if(numbytes!=echostringlen)
                fputs("sent unexpected number of bytes",stdout);
        }
        pthread_exit(NULL);
}

/*void *Receive(void *thread_arg)
{
        int MAXSTRINGLENGTH = 500;
        struct sockaddr_storage fromAddr;
        int numbytesrecv;
        char buffer[MAXSTRINGLENGTH + 1];
        printf("in receive thread \n");
        socklen_t fromAddrLen=sizeof(fromAddr);
        while(1)
        {
        numbytesrecv = recvfrom(sock,buffer,MAXSTRINGLENGTH,0,(struct sockaddr *) &fromAddr, &fromAddrLen);
        if (numbytesrecv<0)
                printf("recvfrom() failed");
        printf("Received :%s \n", buffer);
        memset(buffer,0,sizeof(buffer));
        }
        pthread_exit(NULL);
}*/


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


void doHandshake()
{ 
    hellomsg.mid=MSG_CA_HELLO;
    strcpy(hellomsg.szMessage, "hello");
    
    vWriteToBuffer(&hellomsg, sizeof(hellomsg));   

     if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed connection unexpectedly!");
        else
            loginfo("Failed to send handshake response packet (%s)", strerror(iRetVal));
       // goto error_return;
    }
    
    loginfo("Waiting for response to hello");
    if(!fRecvBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed socket unexpectedly!");
        else
            loginfo("Failed to receive handshake packet (%s)", strerror(iRetVal));
        return;
        //goto error_return;
    }
    if(!fDeconstructPacket(g_pCliSharedKey->abKey, g_pbCliHMACKey, lg_abSRBuffer,
            sizeof(lg_abSRBuffer), &iMIDReply, &nSizeReply, (void**)&pAccessResponse))
    {
        logwarn("Error in decrypting packet");
        return;
       // goto error_return;
    }
    if(iMIDReply != MSG_AC_CHALLENGE)
    {
        loginfo("Invalid message ID received %d", iMIDReply);
        return;
        //goto error_return;
    }
    challengenonce=pAccessResponse->u32Challenge;
    gcry_create_nonce(&myNonce, sizeof(uint32_t));
    logdbg("Sending challenge: %u", myNonce);
    
    handShake.u32Challenge = myNonce;
    handShake.u32Response = challengenonce+1;
    
    if((pvSendPacket = pvConstructPacket(MSG_CA_RESPCHAL, &handShake, sizeof(handShake),
            g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES,
            g_pbCliHMACKey, CRYPT_KEY_SIZE_BYTES,
            &nSendPacketSize)) == NULL )
    {
        logwarn("Unable to create handshake packet!");
        return;
        //goto error_return;
    }
    
    vWriteToBuffer(pvSendPacket, nSendPacketSize);
    
    free(pvSendPacket); pvSendPacket = NULL;
    
    if(!fSendBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed connection unexpectedly!");
        else
            loginfo("Failed to send handshake packet (%s)", strerror(iRetVal));
        //goto error_return;
    }
    
    loginfo("Waiting for response to challenge");
    if(!fRecvBuffer(&iRetVal))
    {
        if(iRetVal == ERR_SOCKET_DOWN)
            loginfo("Accessnode closed socket unexpectedly!");
        else
            loginfo("Failed to receive handshake packet (%s)", strerror(iRetVal));
        return;
        //goto error_return;
    }
    
    if(!fDeconstructPacket(g_pCliSharedKey->abKey, g_pbCliHMACKey, lg_abSRBuffer,
            sizeof(lg_abSRBuffer), &iMIDReply, &nSizeReply, (void**)&pAccessResponse))
    {
        logwarn("Error in decrypting packet");
        return;
        //goto error_return;
    }
    if(iMIDReply != MSG_AC_CHALRESP)
    {
        loginfo("Invalid message ID received %d", iMIDReply);
        return;
        //goto error_return;
    }
    if(pAccessResponse->u32Response != myNonce+1)
    {
        loginfo("Invalid response to challenge received: %u", pAccessResponse->u32Response);
        return;
       // goto error_return;
    }
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
