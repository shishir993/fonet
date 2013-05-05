#ifndef _PACKET_H
#define _PACKET_H

#include <stdint.h>
#include <sys/time.h>
#include "defs.h"
#include "cutils.h"


// message types
// Client to Accessnode
#define MSG_CA_HELLO        100
#define MSG_CA_RESPCHAL     101
#define MSG_CA_SERV_LOGIN   102
#define MSG_CA_SERV_DATA    103

// Accessnode to client
#define MSG_AC_CHALLENGE    130
#define MSG_AC_CHALRESP     131
#define MSG_AC_SESS_EST     132
#define MSG_AC_SERV_DATA    133


// Client to Server
#define MSG_CS_LOGIN        160
#define MSG_CS_ENCODE       161
#define MSG_CS_DECODE       162
#define MSG_CS_LOGOUT       163

// Server to Client
#define MSG_SC_SESSION_KEY  190
#define MSG_SC_OP_SUCCESS   191
#define MSG_SC_OP_FAIL      192
#define MSG_SC_REPLY        193


// Accessnode to Server
#define MSG_AS_CLI_AUTH     220
#define MSG_AS_CLI_REQ      221

// Server to Accessnode
#define MSG_SA_CLI_ACCEPT   250
#define MSG_SA_CLI_REJECT   251
#define MSG_SA_CLI_DATA     252
#define MSG_SA_CLI_DANGER   253
#define MSG_SA_CLI_TERM     254


/* structures */


typedef struct _helloPacket {
    int mid;
    char szMessage[MAX_REQ_STR+1];
}HELLO_PACKET;

// Handshake structure
typedef struct _handshake {
    uint32_t u32Challenge;
    uint32_t u32Response;
}HANDSHAKE;


// 
typedef struct _loginCred {
    char szUsername[MAX_USERNAME+1];
    char szPassphrase[MAX_PASSWD+1];
}LOGIN_CRED;


// Unique data that is the access_token
// HMAC ensures tamper detection
typedef struct _atoken {
    BYTE abHmacCSIPTime[CRYPT_HASH_SIZE_BYTES]; // hmac(clientIP+serverIP+timeval)
    struct timeval tvExpiry;                    // expires 24hrs after issue
}ATOKEN;


#endif // _PACKET_H
