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


int g_nListenPort;
int g_nServerPort;
struct in_addr g_iaServAddr;
char *pszServAddrStr;

SHARED_KEY  *g_pCliSharedKey;    // to store client-accessnode shared keys
BYTE *g_pbCliHMACKey;            // hmac key for client: hash(cli shared key)
SHARED_KEY  *g_pServerSK;        // pointer to accessnode-server shared key
BYTE *g_pbANSecretKey;


// functions
BOOL fCmdLineArgs(int nArgs, char **aszArgs);
BOOL fLoadSharedKeys();
void vDumpSharedKeys();
BOOL fGenHMACKey();
BOOL fCreateANSecretKey();


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
    
    if(!fLoadSharedKeys())
    {
        retVal = ERR_GEN;
        goto fend;
    }
    
    if((g_pbCliHMACKey = pbGenHMACKey(g_pCliSharedKey, CRYPT_KEY_SIZE_BYTES)) == NULL)
    {
        retVal = ERR_GEN;
        goto fend;
    }
    
    if(!fCreateANSecretKey())
    {
        retVal = ERR_GEN;
        goto fend;
    }
    
#ifdef _DEBUG
    vDumpSharedKeys();
    printf("Cli HMAC Key: ")
    vPrintBytes(g_pbCliHMACKey, CRYPT_KEY_SIZE_BYTES);
    printf("AN Secret Key: ");
    vPrintBytes(g_pbANSecretKey, CRYPT_KEY_SIZE_BYTES);
#endif

    if(!fConnectToServer())
    {
        retVal = ERR_GEN;
        goto fend;
    }


    while(1)
    {
        // create client listen socket
        // wait for client's connect()
        if(!fStartClientListen(&iCliSocket))
        {
            retVal = ERR_GEN;
            goto fend;
        }
        
    }
    
    // call comm_handler
    
    fend:
    if(g_pCliSharedKey) vSecureFree(g_pCliSharedKey);
    if(g_pServerSK) vSecureFree(g_pServerSK);
    if(g_pbANSecretKey) vSecureFree(g_pbANSecretKey);
    if(g_pbCliHMACKey) vSecureFree(g_pbCliHMACKey);
    vServCloseSocket();
    if(iCliSocket != -1) free(iCliSocket);
    loginfo("main thread quitting...");

    return retVal;
}


BOOL fLoadSharedKeys()
{
    int fds = -1;
    int fdc = -1;
    
    ssize_t uBytesRead = 0;

    void *pvSecMem = NULL;
    
    
    // first, the accessnode-server shared key
    if((fds = open(AN_SERV_SK_FILE, O_RDONLY, 0)) == -1)
    { logerr("%s open() ", AN_SERV_SK_FILE); goto error_return; }
    
    // allocate memory from secure pool
    if(!fSecureAlloc(sizeof(SHARED_KEY), &pvSecMem))
    { logerr("fLoadSharedKeys(): Could not allocate secure memory"); goto error_return; }
    g_pServerSK = (SHARED_KEY*)pvSecMem;
    
    if((uBytesRead = read(fds, g_pServerSK, sizeof(SHARED_KEY))) != sizeof(SHARED_KEY))
    {
        logerr("fLoadSharedKeys(): read() ");
        goto error_return;
    }
    
    // now, the client-accessnode shared key
    if((fdc = open(AN_CLI_SK_FILE, O_RDONLY, 0)) == -1)
    { logerr("%s open() ", AN_SERV_SK_FILE); goto error_return; }
    
    if(!fSecureAlloc(sizeof(SHARED_KEY), &pvSecMem))
    { logerr("fLoadSharedKeys(): Could not allocate secure memory"); goto error_return; }
    g_pCliSharedKey = (SHARED_KEY*)pvSecMem;
    
    if((uBytesRead = read(fdc, g_pCliSharedKey, sizeof (SHARED_KEY))) != sizeof(SHARED_KEY))
    {
        logerr("read() ");
        goto error_return;
    }
    else
    {
        logdbg("Record %d", nRecords);
        logdbg("Alice: %s\nBob: %s", pskTemp->szAlice, pskTemp->szBob);
        logdbg("Shared key: ");
        vPrintBytes(g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES);
    }
    
    close(fds);
    close(fdc);
    return TRUE;
    
    error_return:
    if(fds != -1) close(fds);
    if(fdc != -1) close(fdc);
    if(g_pServerSK) vSecureFree(g_pServerSK);
    if(g_pCliSharedKey) vSecureFree(g_pCliSharedKey);
    return FALSE;

}// fLoadSharedKeys()


void vDumpSharedKeys()
{
    loginfo("Shared keys read from files...");
    
    printf("Server shared key: \n");
    printf("Alice: %s\n", g_pServerSK->szAlice);
    printf("Bob  : %s\n", g_pServerSK->szBob);
    printf("Key  : ");
    vPrintBytes(g_pServerSK->abKey, CRYPT_KEY_SIZE_BYTES);
    
    printf("Client shared key...\n");
    printf("Alice: %s\n", g_pCliSharedKey->szAlice);
    printf("Bob  : %s\n", g_pCliSharedKey->szBob);
    printf("Key  : ");
    vPrintBytes(g_pCliSharedKey->abKey, CRYPT_KEY_SIZE_BYTES);
    
    loginfo("END...");
    return;
}


BOOL fCreateANSecretKey()
{
    if(!fSecureAlloc(CRYPT_KEY_SIZE_BYTES, (void**)&g_pbANSecretKey))
        return FALSE;
    
    gcry_create_nonce(g_pbANSecretKey, CRYPT_KEY_SIZE_BYTES);
    return TRUE;
}


BOOL fCmdLineArgs(int nArgs, char **aszArgs)
{
    ASSERT(aszArgs);
    
    // usage: ./accessnode <listenPort> <serverIP> <serverPort>
    if(nArgs != 4)
    {
        loginfo("usage: %s <listenPort> <serverIP> <serverPort>\n", aszArgs[0]);
        goto error_return;
    }
    
    g_nListenPort = atoi(aszArgs[1]);
    if(g_nListenPort <= 1023 && g_nListenPort > 65535)
    {
        loginfo("Invalid listen port %d", g_nListenPort);
        goto error_return;
    }
    
    g_nServerPort = atoi(aszArgs[3]);
    if(g_nServerPort <= 1023 && g_nServerPort > 65535)
    {
        loginfo("Invalid server port %d", g_nServerPort);
        goto error_return;
    }
    
    pszServAddrStr = aszArgs[2];
    if( inet_pton(AF_INET, aszArgs[2], &g_iaServAddr) != 1 )
    {
        loginfo("Unable to convert server address %s to binary form", aszArgs[2]);
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    return FALSE;
    
}// fCmdLineArgs()








BOOL fUnitTests()
{
    // first, the hash table
    struct in_addr addr1;
    struct in_addr addr2;
    struct in_addr addr3;
    struct in_addr addr4;
    struct in_addr addr5;
    
    pthread_t tid1;
    pthread_t tid2;
    pthread_t tid3;
    pthread_t tid4;
    
    pthread_t tidn1, tidn2, tidn3, tidn4;
    QUEUE *pqueue = NULL, *pnewpointer = NULL;
    HTABLE *pht = NULL;

    
    void *pval = NULL;
    int valsize = 0;
    
    if(!HT_fCreate(&pht, 4, HT_KEY_UINT, HT_VAL_VOIDP))
        return FALSE;
    
    if(!Q_fCreate(&pqueue))
        return FALSE;
    
    addr1.s_addr = inet_addr("127.0.0.1");
    addr2.s_addr = inet_addr("10.171.70.120");
    addr3.s_addr = inet_addr("10.171.70.121");
    addr4.s_addr = inet_addr("10.171.70.122");
    addr5.s_addr = inet_addr("192.168.0.1");
    
    pthread_create(&tid1, NULL, pvTestThread, NULL);
    pthread_create(&tid2, NULL, pvTestThread, NULL);
    pthread_create(&tid3, NULL, pvTestThread, NULL);
    pthread_create(&tid4, NULL, pvTestThread, NULL);
    
    if(!HT_fInsert(pht, &addr1.s_addr, sizeof(in_addr_t), &tid1, sizeof(pthread_t)))
        logwarn("Hash insert didn't work");
    
    pqueue->numElems = 0xdead;
    pqueue->pfront = (QNODE*)0xbeefbeef;
    pqueue->prear = (QNODE*)0xcdcdcdcd;
    
    if(!HT_fInsert(pht, &addr4.s_addr, sizeof(in_addr_t), &pqueue, sizeof(QUEUE*)))
        logwarn("Hash find didn't work");
                
    if(!HT_fInsert(pht, &addr2.s_addr, sizeof(in_addr_t), &tid2, sizeof(pthread_t)))
        logwarn("Hash insert didn't work");
    
    if(!HT_fFind(pht, &addr1.s_addr, sizeof(in_addr_t), &pval, &valsize))
        logwarn("Hash find didn't work");
    
    
    if(!HT_fFind(pht, &addr3.s_addr, sizeof(in_addr_t), &pval, &valsize))
        logwarn("Hash find didn't work");
    
    if(!HT_fInsert(pht, &addr3.s_addr, sizeof(in_addr_t), &tid3, sizeof(pthread_t)))
        logwarn("Hash find didn't work");
    
    if(!HT_fFind(pht, &addr3.s_addr, sizeof(in_addr_t), &pval, &valsize))
        logwarn("Hash find didn't work");
    
    if(!HT_fFind(pht, &addr4.s_addr, sizeof(in_addr_t), &pval, &valsize))
        logwarn("Hash find didn't work");
    
    memcpy(&pnewpointer, pval, valsize);
    
    if(!HT_fRemove(pht, &addr4.s_addr, sizeof(in_addr_t)))
        logwarn("Hash remove didn't work");
    
    if(!HT_fFind(pht, &addr4.s_addr, sizeof(in_addr_t), &pval, &valsize))
        logwarn("Hash find 4 didn't work");
    
    if(!HT_fFind(pht, &addr3.s_addr, sizeof(in_addr_t), &pval, &valsize))
        logwarn("Hash find didn't work");
    
    if(!HT_fDestroy(pht))
        logwarn("hash table destroy failed");
    
    pqueue->pfront = NULL;
    pqueue->prear = NULL;
    if(!Q_fDestroy(pqueue))
        logwarn("queue destroy didn't work");
    
    return TRUE;
    
}// fUnitTests()
