/* 
 * File:   clihandler.h
 * Author: shishir
 *
 * Created on April 24, 2013, 9:46 AM
 */

#ifndef _CLIHANDLER_H
#define	_CLIHANDLER_H

#include "aninclude.h"
#include "../common/helpers.h"


// states
#define CHS_HELLO_WAIT          10
#define CHS_HANDSHAKE           11
#define CHS_LOGIN_WAIT          12
#define CHS_SERV_WAIT           13
#define CHS_CLI_LOGIN_FAILED    14
#define CHS_BEGIN_SESSION       15
#define CHS_DATA_FORWARD        16
#define CHS_TERMINATE           17


BOOL fStartClientListen(int *piCliSocket);
BOOL fCliCommHandler(int iCliSocket);

#endif	/* _CLIHANDLER_H */

