
#ifndef _DEFS_H
#define _DEFS_H


// defines
#define TRUE	1
#define FALSE	0

// MAX string values
#define MAX_PATH    255
#define MAX_PASSWD   31

// time values
#define TIME_TWO_SEC            2
#define TIME_THREE_SEC          3
#define TIME_QUAR_SEC_MICRO     250000
#define TIME_HALF_SEC_MICRO     500000

// error codes
#define ERR_NONE        0
#define ERR_GEN         100     // general error
#define ERR_SOCKET      101     // general socket error
#define ERR_SOCKET_DOWN 102
#define ERR_NO_MEM      103     // if out of memory or output buffer size is lower than required

#define ERR_KEYSIZE     120     // key is not of the required size
#define ERR_ENCRYPT     121     // error during encryption
#define ERR_DECRYPT     122
#define ERR_IN_SIZE     123     // input size is invalid
#define ERR_HASHGEN     124     // error generating hash

#define SERVER_PORT		34678

#define SR_BUFSIZE      512     // socket send/receive buffer size


//
typedef int BOOL;
typedef unsigned char BYTE;

#endif // _DEFS_H