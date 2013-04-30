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
#define MSG_CS_REQUEST      161
#define MSG_CS_LOGOUT       162

// Server to Client
#define MSG_SC_ACC_TOKEN    190
#define MSG_SC_REPLY        191


// Accessnode to Server
#define MSG_AS_CLI_AUTH     220
#define MSG_AS_CLI_REQ      221

// Server to Accessnode
#define MSG_SA_CLI_ACCEPT   250
#define MSG_SA_CLI_DATA     251
#define MSG_SA_CLI_DANGER   252
#define MSG_SA_CLI_TERM     253


/* structures */

// Send/receive buffer
struct _srbuffer {
    BYTE abBuffer[SR_BUFSIZE];
}SR_BUFFER;


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
    BYTE abPassword[CRYPT_HASH_SIZE_BYTES];
}LOGIN_CRED;


typedef struct _servSessionKey {
    BYTE abKey[CRYPT_KEY_SIZE_BYTES];
}SERV_SKEY;


// Unique data that is the access_token
// This MUST be encrypted and a hmac value must be
// tagged along with this to detect tampering.
typedef struct _anUniqData {
    BYTE abHmacCSIP[CRYPT_HASH_SIZE_BYTES];
    struct timeval tvGenerated;
}AN_UNIQDATA;


#endif // _PACKET_H
