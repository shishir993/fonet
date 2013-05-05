/* 
 * File:   aninclude.h
 * Author: shishir
 *
 * Created on April 24, 2013, 9:41 AM
 */

#ifndef _ANINCLUDE_H
#define	_ANINCLUDE_H


#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

// open()
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// signals
#include <signal.h>

// threads
#include <pthread.h>

// sockets
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// user includes
#include "../common/assert.h"
#include "../common/sdbg.h"
#include "../common/defs.h"
#include "../common/packet.h"

            
#define AN_CLI_SK_FILE      "../etc/an_sharedkeys.dat"         // client shared key file
#define AN_SERV_SK_FILE     "../etc/an_server_sharedkey.dat"   // server shared key file


#endif	/* _ANINCLUDE_H */
