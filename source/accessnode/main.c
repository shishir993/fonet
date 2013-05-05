/* 
 * File:   main.c
 * Author: 
 *
 * Created on April 16, 2013, 5:22 PM
 */

#include "aninclude.h"
#include "scomm.h"

#include "../common/cutils.h"
#include "../common/hashtable.h"
#include "../common/queue.h"


#define FILE_SECRET_KEY     "../etc/an_secretkey.dat"


// global variables
struct in_addr g_iaServAddr;
char *pszServAddrStr;

SHARED_KEY  *g_pCliSharedKey;   // to store client-accessnode shared keys
BYTE *g_pbCliHMACKey;           // hmac key for client: hash(cli shared key)

SHARED_KEY  *g_pServerSK;       // pointer to accessnode-server shared key
BYTE *g_pbServerHMACKey;        // hmac key for server: hash(serv shared key)

BYTE *g_pbANSecretKey;


// functions
static BOOL fCmdLineArgs(int nArgs, char **aszArgs);
static BOOL fDoLoadGenKeys();
static BOOL fLoadSecretKeyFile();
static void vDumpKeys();


/*
 * 
 */
int main(int argc, char** argv)
{
    int retVal = ERR_NONE;
    int iCliSocket = -1;

    
    if(!fInitGCrypt())
        return 1;
    
    if(!fCmdLineArgs(argc, argv))
        return ERR_GEN;
    
    if(!fDoLoadGenKeys())
    { retVal = ERR_GEN; goto fend; }
    
    
#ifdef _DEBUG
    vDumpKeys();
#endif

    if(!fConnectToServer())
    { retVal = ERR_GEN; goto fend; }

    while(1)
    {
        // create client listen socket
        // wait for client's connect()
        if(!fStartClientListen(&iCliSocket))
        { retVal = ERR_SOCKET; goto fend; }
        
        // call comm_handler
        fCliCommHandler(iCliSocket);
        
        loginfo("Going back to listening for a client...");
    }
    
    fend:
    if(g_pCliSharedKey) vSecureFree(g_pCliSharedKey);
    if(g_pServerSK) vSecureFree(g_pServerSK);
    if(g_pbANSecretKey) vSecureFree(g_pbANSecretKey);
    if(g_pbCliHMACKey) vSecureFree(g_pbCliHMACKey);
    vServCloseSocket();
    if(iCliSocket != -1) close(iCliSocket);
    loginfo("accessnode shutting down...");

    return retVal;
}


static BOOL fDoLoadGenKeys()
{   
    // first, load the shared keys: anode-server key AND anode-client key
    
    if(!fLoadSharedKeyFile(AS_SK_FILE, &g_pServerSK))
    { logwarn("Could not load AS shared key file"); goto error_return; }
    
    if(!fLoadSharedKeyFile(CA_SK_FILE, &g_pCliSharedKey))
    { logwarn("Could not load AC shared key file"); goto error_return; }
    
    // generate HMAC keys for each
    if((g_pbCliHMACKey = pbGenHMACKey(g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    { logwarn("Could not generate client HMAC key"); goto error_return; }
    
    if((g_pbServerHMACKey = pbGenHMACKey(g_pServerSK->abKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    { logwarn("Could not generate server HMAC key"); goto error_return; }
    
    if(!fLoadSecretKeyFile())
    { logwarn("Could not generate anode secret key"); goto error_return; }

    return TRUE;
    
    error_return:
    if(g_pServerSK) vSecureFree(g_pServerSK);
    if(g_pCliSharedKey) vSecureFree(g_pCliSharedKey);
    if(g_pbCliHMACKey) vSecureFree(g_pbCliHMACKey);
    if(g_pbServerHMACKey) vSecureFree(g_pbServerHMACKey);
    return FALSE;

}// fDoLoadGenKeys()


static void vDumpKeys()
{
    loginfo("Keys dump...");
    
    printf("Server shared key: ");
    vPrintBytes(g_pServerSK->abKey, CRYPT_KEY_SIZE_BYTES);
    printf("Server HMAC key  : ");
    vPrintBytes(g_pbServerHMACKey, CRYPT_KEY_SIZE_BYTES);
    
    printf("Client shared key:");
    vPrintBytes(g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES);
    printf("Client HMAC key  : ");
    vPrintBytes(g_pbCliHMACKey, CRYPT_KEY_SIZE_BYTES);

    printf("Anode secret key : ");
    vPrintBytes(g_pbANSecretKey, CRYPT_KEY_SIZE_BYTES);
    
    loginfo("END...");
    return;
}


static BOOL fLoadSecretKeyFile()
{
    int fd = -1;
    BOOL fFileFound = FALSE;
    
    BYTE abKey[CRYPT_KEY_SIZE_BYTES];
    
    
    if((fd = open(FILE_SECRET_KEY, O_RDONLY, 0)) == -1)
        logwarn("%s not found. Will generate a new secret key.", FILE_SECRET_KEY);
    else
        fFileFound = TRUE;
    
    if(fFileFound)
    {
        if( read(fd, abKey, CRYPT_KEY_SIZE_BYTES) != CRYPT_KEY_SIZE_BYTES )
        {
            logerr("read() ");
            goto error_return;
        }
        close(fd);
        fd = -1;
        
        if(!fSecureAlloc(CRYPT_KEY_SIZE_BYTES, (void**)&g_pbANSecretKey))
            return FALSE;
        memcpy(g_pbANSecretKey, abKey, CRYPT_KEY_SIZE_BYTES);
    }
    else
    {
        int openMode = S_IRUSR|S_IWUSR|S_IRGRP;
        
        if(!fSecureAlloc(CRYPT_KEY_SIZE_BYTES, (void**)&g_pbANSecretKey))
            return FALSE;
    
        gcry_create_nonce(g_pbANSecretKey, CRYPT_KEY_SIZE_BYTES);
        
        // write to file
        if((fd = open(FILE_SECRET_KEY, O_WRONLY|O_CREAT|O_TRUNC, openMode)) == -1)
            logwarn("Could not write to %s", FILE_SECRET_KEY);
        if( write(fd, g_pbANSecretKey, CRYPT_KEY_SIZE_BYTES) != CRYPT_KEY_SIZE_BYTES )
            logwarn("write() ");
        close(fd);
        fd = -1;
    }
    
    return TRUE;
    
    error_return:
    if(fd != -1) close(fd);
    return FALSE;
}


static BOOL fCmdLineArgs(int nArgs, char **aszArgs)
{
    ASSERT(aszArgs);
    
    // usage: ./accessnode <serverIP>
    if(nArgs != 2)
    {
        loginfo("usage: %s <serverIP>\n", aszArgs[0]);
        goto error_return;
    }

    pszServAddrStr = aszArgs[1];
    if( inet_pton(AF_INET, aszArgs[1], &g_iaServAddr) != 1 )
    {
        loginfo("Unable to convert server address %s to binary form", aszArgs[1]);
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    return FALSE;
    
}// fCmdLineArgs()
