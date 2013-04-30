/* 
 * File:   clihandler.h
 * Author: shishir
 *
 * Created on April 24, 2013, 9:46 AM
 */

#ifndef _CLIHANDLER_H
#define	_CLIHANDLER_H

#include "aninclude.h"


// states
#define CHS_HELLO_WAIT      10
#define CHS_HANDSHAKE       11
#define CHS_SERV_WAIT       12
#define CHS_DATA_FORWARD    13
#define CHS_TERMINATE       14


BOOL fStartClientListen(int *piCliSocket);
BOOL fCliCommHandler(int iCliSocket);
//void *pvClientListenThread(void *pvArg);
//
//BOOL fStartClientHandler(int iCliSocket, struct in_addr *pCliAddr);
//void *pvCliHandler(void *pvArg);

#endif	/* _CLIHANDLER_H */

