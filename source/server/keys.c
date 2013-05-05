
#include "keys.h"

#define MAX_LINE    128


int lg_nUsers;
UNAME_PASSWD lg_stUsers[MAX_USERS];


BOOL fLoadUsersFromFile(const char *pszFilepath)
{
    ASSERT(pszFilepath);
    
    FILE *fp = NULL;

    char ch;
    int nCharsInLine;
    char *psz = NULL;
    char szLine[MAX_LINE+1];
    
    int nSaltLen = 0;
    int nHashLen = 0;
    BYTE *pbSalt = NULL;
    BYTE *pbHash = NULL;
    
    // open file
    if((fp = fopen(pszFilepath, "r")) == NULL)
    {
        logerr("fopen() ");
        goto error_return;
    }
    
    while(lg_nUsers < MAX_USERS)
    {
        pbHash = pbSalt = NULL;
        nHashLen = nSaltLen = 0;
        
        nCharsInLine = 0;
        memset(szLine, 0, sizeof(szLine));
        
        psz = szLine;
        while( nCharsInLine++ <= MAX_LINE )
        {
             ch = fgetc(fp);
             if(ch == '\n') break;
             if(ch == EOF) goto fend;
             *psz++ = ch;
        }
        if(nCharsInLine > MAX_LINE && ch != '\n')
        {
            logwarn("Line too long!!");
            goto error_return;
        }
        *psz = 0;
        
#ifdef _DEBUG
      printf("Read line: \"%s\"\n", szLine);
#endif
      
      // username first
      if((psz = strtok(szLine, ":")) == NULL)
      {
          logwarn("Couldn't tokenize to find username");
          goto error_return;
      }
      
      strncpy(lg_stUsers[lg_nUsers].szUsername, psz, sizeof(lg_stUsers[lg_nUsers].szUsername));
      
      // now, salt
      if((psz = strtok(NULL, ":")) == NULL)
      {
          logwarn("Couldn't tokenize to find salt");
          goto error_return;
      }
      
      printf("Salt: %s\n", psz);
      
      if((pbSalt = unbase64(psz, strlen(psz), &nSaltLen)) == NULL)
      {
          logwarn("Could not decode salt");
          goto error_return;
      }
      
      // now, hash
      if((psz = strtok(NULL, "\n")) == NULL)
      {
          logwarn("Couldn't tokenize to find hash");
          goto error_return;
      }
      
      printf("Hash: %s\n", psz);
      
      if((pbHash = unbase64(psz, strlen(psz), &nHashLen)) == NULL)
      {
          logwarn("Could not decode hash");
          goto error_return;
      }
      
      printf("Username: %s\n", lg_stUsers[lg_nUsers].szUsername);
      printf("Salt: ");
      vPrintBytes(pbSalt, CRYPT_SALT_SIZE_BYTES);
      printf("Hash: ");
      vPrintBytes(pbHash, CRYPT_HASH_SIZE_BYTES);
      
      memcpy(lg_stUsers[lg_nUsers].abSalt, pbSalt, nSaltLen);
      memcpy(lg_stUsers[lg_nUsers].abDerivedKey, pbHash, nHashLen);
      ++lg_nUsers;
      
      free(pbSalt);
      free(pbHash);
      
    }// while
    
    fend:
    fclose(fp);
    fp = NULL;
    
    loginfo("nUsers = %d", lg_nUsers);
    return TRUE;
    
    error_return:
    if(fp) fclose(fp);
    return FALSE;
}


BOOL fVerifyUserGetKey(const char *pszUsername, const char *pszPassphrase)
{
    ASSERT(pszUsername && pszPassphrase);
    
    int i = 0;
    BYTE abDerivedKey[CRYPT_KEY_SIZE_BYTES];

    
    // find the user first
    for(; i < lg_nUsers; ++i)
        if(strcmp(lg_stUsers[i].szUsername, pszUsername) == 0)
            break;
    
    if(i == lg_nUsers)
        return FALSE;
    
    if(!fPassphraseSaltToKey(pszPassphrase, strlen(pszPassphrase),
            lg_stUsers[i].abSalt, CRYPT_SALT_SIZE_BYTES,
            abDerivedKey, CRYPT_KEY_SIZE_BYTES))
    {
        logwarn("Error converting passphrase to key");
        return FALSE;
    }
    
    if(fCompareBytes(lg_stUsers[i].abDerivedKey, CRYPT_KEY_SIZE_BYTES,
            abDerivedKey, CRYPT_KEY_SIZE_BYTES))
    {
        return TRUE;
    }
    
    return FALSE;

}// fVerifyUserGetKey
