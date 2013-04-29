
#include "clihandler.h"


extern int g_nListenPort;

/**
 * 
 * @param ptid
 * @return 
 */
BOOL fStartClientListen(int *piCliSocket)
{
    ASSERT(piCliSocket);
    ASSERT(g_nListenPort >= 1024 && g_nListenPort <=65535);

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
    myAddr.sin_port = htons(g_nListenPort);
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
            g_nListenPort);
    
    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(lg_iListenSocket, &readfds);

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
    
    loginfo("fStartClientListen(): New connection from %s\n", inet_ntoa(saClientAddr.sin_addr));
    
    close(iListenSocket);
    *piCliSocket = iNewSocket;
    return TRUE;
    
    error_return:
    if(iListenSocket != -1) { close(iListenSocket); iListenSocket  = -1; }
    *piCliSocket = -1;
    return FALSE;
    
}// fStartClientListen()


/**
 * Client listen thread entry point
 * @param pvArg
 * @return 
 */
//void *pvClientListenThread(void *pvArg)
//{
//    int iNewSocket = -1;
//    struct timeval tvTimeout;
//
//    fd_set readfds;
//
//    socklen_t CliAddrLen;
//    struct sockaddr_in saClientAddr;
//    
//    
//    loginfo("pvClientListenThread() started: Listening on socket %d at port %d", iListenSocket, 
//            g_nListenPort);
//    
//    while(1)
//    {
//        FD_ZERO(&readfds);
//        FD_SET(iListenSocket, &readfds);
//
//        // set timeout as half a second
//        tvTimeout.tv_sec = 0;
//        tvTimeout.tv_usec = TIME_HALF_SEC_MICRO;
//
//        if( select(iListenSocket+1, &readfds, NULL, NULL, &tvTimeout) == -1 )
//        {
//            logerr("pvClientListenThread(): select() ");
//            sleep(TIME_THREE_SEC);
//            continue;
//        }
//
//        if( FD_ISSET(iListenSocket, &readfds) )
//        {
//            CliAddrLen = sizeof(struct sockaddr_in);
//
//            // there is an incoming connection
//            iNewSocket = accept(iListenSocket, (struct sockaddr*)&saClientAddr, &CliAddrLen);
//            if(iNewSocket == -1)
//            {
//                logerr("pvClientListenThread(): accept() ");
//                sleep(TIME_ONE_SEC);
//                continue;
//            }
//
//            loginfo("pvClientListenThread(): New connection from %s\n", inet_ntoa(saClientAddr.sin_addr));
//
//            // connection accepted, create a thread to communicate with the client
//            // closing this new socket is the responsibility of the client handler
//            if( ! fStartClientHandler(iNewSocket, &saClientAddr.sin_addr) )
//            {
//                logerr("pvClientListenThread(): Could not start client handler\n");
//                continue;
//            }
//
//            // continue listening for other clients
//
//        }// if FD_SET
//    }// while(1)
//    
//    loginfo("pvClientListenThread(): Closing socket %d at port %d", iListenSocket, 
//            g_nListenPort);
//    close(iListenSocket);
//    iListenSocket = -1;
//    
//    pthread_exit((void*)0);
//
//}// pvClientListenThread()


/**
 * 
 * @param iCliSocket
 * @param pCliAddr
 * @return 
 */
//BOOL fStartClientHandler(int iCliSocket, struct in_addr *pCliAddr)
//{
//    int iRetVal = 0;
//
//    CLIENT_DATA *pstCHThreadArgs = NULL;
//
//    pthread_attr_t attr;
//    pthread_t tidThread;
//
//
//    if( (pstCHThreadArgs = (CLIENT_DATA*)malloc(sizeof(CLIENT_DATA))) == NULL )
//    {
//        logerr("CH_fStartClientHandler(): malloc() ");
//        goto error_return;
//    }
//
//    pstCHThreadArgs->iCliSocket = iCliSocket;
//    pstCHThreadArgs->cliAddr.s_addr = pCliAddr->s_addr;
//
//    // set thread as joinable
//    pthread_attr_init(&attr);
//    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
//
//    // create the thread
//    if( (iRetVal = pthread_create(&tidThread, &attr, pvCliHandler, (void*)pstCHThreadArgs)) != 0 )
//    {
//        logerr("fStartClientHandler(): pthread_create() ");
//        pthread_attr_destroy(&attr);
//        goto error_return;
//    }
//
//    pthread_attr_destroy(&attr);
//    return TRUE;
//    
//    error_return:
//    return FALSE;
//
//}// fStartClientHandler()
//
//
//
///**
// * Client handler thread entry point
// * @param pvArg
// * @return 
// */
//void *pvCliHandler(void *pvArg)
//{
//    ASSERT(pvArg);
//    
//    int state;
//    int clisocket;
//    struct in_addr cliaddr;
//    CLIENT_DATA *pCliData = (CLIENT_DATA*)pvArg;
//    
//    ASSERT(pCliData->iCliSocket > 0);
//    clisocket = pCliData->iCliSocket;
//    cliaddr.s_addr = pCliData->cliAddr.s_addr;
//    
//    free(pCliData);
//    pCliData = pvArg = NULL;
//    
//    while(1)
//    {
//        // state machine
//    }// while(1)
//    
//    
//    close(clisocket);
//    pthread_exit((void*)0);
//    
//}// pvCliHandler()
