/* 
 * File:   keys.h
 * Author: shishir
 *
 * Created on May 2, 2013, 10:12 PM
 */

#ifndef _KEYS_H
#define	_KEYS_H


#include <stdio.h>
#include <string.h>

// open()
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// write()
#include <unistd.h>

#include "../common/assert.h"
#include "../common/defs.h"
#include "../common/cutils.h"


#define MAX_USERS   32


typedef struct _unamePasswd {
    char szUsername[MAX_USERNAME+1];
    BYTE abSalt[CRYPT_SALT_SIZE_BYTES];
    BYTE abDerivedKey[CRYPT_KEY_SIZE_BYTES];
    
}UNAME_PASSWD;


BOOL fLoadUsersFromFile(const char *pszFilepath);
BOOL fVerifyUserGetKey(const char *pszUsername, const char *pszPassphrase,
        BYTE **pbKeyOut);

#endif	/* KEYS_H */

