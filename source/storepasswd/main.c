/* 
 * File:   main.c
 * Author: shishir
 *
 * Created on April 27, 2013, 8:18 AM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// open()
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// write()
#include <unistd.h>

#include <sys/time.h>

#include "../common/assert.h"
#include "../common/defs.h"
#include "../common/sdbg.h"
#include "../common/cutils.h"
#include "../common/base64/base64.h"


#define FTYPE_UP    1   // user/passwd file
#define FTYPE_SK    2   // shared key file

// functions
BOOL fWriteToFile(int fd, void *pvData, int dataSize);
void vDisplayRecords(int fd, int ftype);

void vUserPasswdFile();
void vSharedKeyFile();

/*
 * 
 */
int main() {
    int userOption = -1;

    if (!fInitGCrypt())
        return 1;

    while (userOption != 5) 
    {
        printf("\nMenu\n1. Username/password file\n2. Shared key file\n");
        printf("3. Display username/password file\n4. Display shared key file\n");
        printf("5. Quit\n? ");
        scanf("%d", &userOption);
        switch (userOption) 
        {
            case 1:
                vUserPasswdFile();
                break;

            case 2:
                vSharedKeyFile();
                break;

            case 3:
            case 4:
            {
                int fd = -1;
                int flags = O_RDONLY;
                char szFilepath[MAX_PATH+1];
                
                printf("Enter filename: ");
                fReadLineFromStdin(szFilepath, MAX_PATH+1);
                if((fd = iOpenFile(szFilepath, flags)) == -1)
                { logerr("open() "); break; }
                if(userOption == 3)
                    vDisplayRecords(fd, FTYPE_UP);
                else
                    vDisplayRecords(fd, FTYPE_SK);
                close(fd);
                fd = -1;
                break;
            }
            
            case 5:
                break;
            
            default: printf("Invalid option. Try again.\n");
                break;
        }
    }

    return (EXIT_SUCCESS);
}


BOOL fWriteToFile(int fd, void *pvData, int dataSize)
{
    ASSERT(fd > 0 && pvData && dataSize > 0);

    ssize_t uBytesWritten;

    uBytesWritten = write(fd, pvData, dataSize);
    if (uBytesWritten != dataSize) 
    {
        logerr("write() failed ");
        return FALSE;
    }
    return TRUE;

}


void vDisplayRecords(int fd, int ftype)
{
    ssize_t uBytesRead = 0;
    char *szB64Decoded = NULL;
    char *pch = NULL;
    int nB64DecodedLen = 0;

    int nRecord = 0;

    if(ftype == FTYPE_UP)
    {
        USER_PASSWD upData;
        while ((uBytesRead = read(fd, &upData, sizeof (USER_PASSWD))) == sizeof (USER_PASSWD)) 
        {
            printf("Record %d\n", nRecord++);
            printf("Username: %s\n", upData.szUsername);
            printf("Salt    : ");
            vPrintBytes(upData.abSalt, CRYPT_SALT_SIZE_BYTES);
            if((szB64Decoded = base64(upData.abSalt, CRYPT_SALT_SIZE_BYTES, 
                    &nB64DecodedLen)) != NULL)
            {
                pch = szB64Decoded;
                while(nB64DecodedLen-- > 0)
                    printf("%c", *pch++);
                printf("\n");
                free(szB64Decoded);
            }
            printf("Key     : ");
            vPrintBytes(upData.abDerivedKey, CRYPT_KEY_SIZE_BYTES);
            if((szB64Decoded = base64(upData.abDerivedKey, CRYPT_KEY_SIZE_BYTES, 
                    &nB64DecodedLen)) != NULL)
            {
                pch = szB64Decoded;
                while(nB64DecodedLen-- > 0)
                    printf("%c", *pch++);
                printf("\n");
                free(szB64Decoded);
            }
            DBG_MEMSET(&upData, sizeof (USER_PASSWD));
        }
    }
    else if(ftype == FTYPE_SK)
    {
        SHARED_KEY skData;
        while ((uBytesRead = read(fd, &skData, sizeof (SHARED_KEY))) == sizeof (SHARED_KEY)) 
        {
            printf("Record %d\n", nRecord++);
            printf("Alice: %s\nBob: %s\n", skData.szAlice, skData.szBob);
            printf("Shared key: ");
            vPrintBytes(skData.abKey, CRYPT_KEY_SIZE_BYTES);
            DBG_MEMSET(&skData, sizeof (SHARED_KEY));
        }
    }
    else
        loginfo("vDisplayRecords(): Invalid file type %d!", ftype);
    
    return;
    
}


void vGetFilePathMode(char *pszFilepath, int *piFlags)
{
    char chMode;
    
    printf("Enter path to file: ");
    fReadLineFromStdin(pszFilepath, MAX_PATH+1);
    printf("Create New or Append? (C/A) ");
    scanf("%c", &chMode);
    while(1)
    {
        if(chMode == 'C' || chMode == 'c')
        {
            *piFlags = O_WRONLY | O_CREAT | O_TRUNC;
            printf("Creating new file %s\n", pszFilepath);
            break;
        }
        else if(chMode == 'A' || chMode == 'a')
        {
            *piFlags = O_WRONLY | O_APPEND;
            printf("Appending to file %s\n", pszFilepath);
            break;
        }
        else
            printf("Invalid mode\n");
    }
    
    return;
}


int iOpenFile(const char *pszFilepath, int flags)
{
    int fd = -1;
    int openPerm = S_IRUSR|S_IWUSR|S_IRGRP;
    
    if((fd = open(pszFilepath, flags, openPerm)) == -1)
    {
        logerr("open(): %s: ", pszFilepath);
        return -1;
    }
    
    return fd;
}


void vUserPasswdFile()
{
    char szFile[MAX_PATH+1];
    char szPassphrase[MAX_PASSWD+1];
    
    char *pszSalt = NULL;
    char *pszHash = NULL;
    int nEncodedLen = 0;
    
    USER_PASSWD upData;
    
    int fd = -1;
    int flags = 0;
    int nRecords = 0;
    int userOption = -1;
    
    vGetFilePathMode(szFile, &flags);
    if((fd = iOpenFile(szFile, flags)) == -1)
    { logerr("open() "); goto fend; }
    
    while(userOption != 2)
    {
        printf("1. Add new record\n2. Quit\n? ");
        scanf("%d", &userOption);
        switch(userOption)
        {
            case 1:
                printf("Enter username: ");
                fReadLineFromStdin(upData.szUsername, MAX_USERNAME+1);
                printf("Enter passphrase: ");
                fReadLineFromStdin(szPassphrase, MAX_PASSWD+1);
                if(!fPassphraseToKey(szPassphrase, strlen(szPassphrase), 
                        upData.abSalt, CRYPT_SALT_SIZE_BYTES,
                        upData.abDerivedKey, CRYPT_KEY_SIZE_BYTES))
                { logwarn("Unable to derive passphrase!"); break; }
                
                printf("Username: %s\n", upData.szUsername);
                printf("Salt: ");
                vPrintBytes(upData.abSalt, CRYPT_SALT_SIZE_BYTES);
                printf("Hash: ");
                vPrintBytes(upData.abDerivedKey, CRYPT_HASH_SIZE_BYTES);
                
                // username:salt:hash'\n'
                if(write(fd, upData.szUsername, 
                        strlen(upData.szUsername)) != strlen(upData.szUsername))
                { logerr("write() "); break; }
                
                if((pszSalt = base64(upData.abSalt, CRYPT_SALT_SIZE_BYTES, 
                        &nEncodedLen)) == NULL)
                {
                    logwarn("Could not convert salt to base64");
                    break;
                }
                
                if(write(fd, ":", 1) != 1)
                { logerr("user : write() "); break; }
                
                // write salt
                if(write(fd, pszSalt, nEncodedLen) != nEncodedLen)
                { logerr("salt write() "); break; }
                
                if(write(fd, ":", 1) != 1)
                { logerr("salt : write() "); break; }
                
                if((pszHash = base64(upData.abDerivedKey, CRYPT_KEY_SIZE_BYTES, 
                        &nEncodedLen)) == NULL)
                {
                    logwarn("Could not convert hash to base64");
                    break;
                }
                
                // write hash
                if(write(fd, pszHash, nEncodedLen) != nEncodedLen)
                { logerr("hash write() "); break; }
                
                if(write(fd, "\n", 1) != 1)
                { logerr("user : write() "); break; }
                free(pszSalt);
                free(pszHash);
                break;
                
            case 2: break;
            default: logwarn("Invalid option!\n"); break;
        }
    }// while(1)
    
    loginfo("Total records written = %d\n", nRecords);
    fend:
    if(fd != -1) close(fd);
    return;
}


void vSharedKeyFile()
{
    char szFile[MAX_PATH+1];
    
    SHARED_KEY skData;
    
    int fd = -1;
    int flags = 0;
    int nRecords = 0;
    int userOption = -1;
    
    vGetFilePathMode(szFile, &flags);
    if((fd = iOpenFile(szFile, flags)) == -1)
    { logerr("open() "); goto fend; }
    
    while(userOption != 2)
    {
        printf("1. Add new record\n2. Quit\n? ");
        scanf("%d", &userOption);
        switch(userOption)
        {
            case 1:
                printf("Enter Alice: ");
                fReadLineFromStdin(skData.szAlice, INET_ADDRSTRLEN+1);
                printf("Enter Bob: ");
                fReadLineFromStdin(skData.szBob, INET_ADDRSTRLEN+1);
                gcry_create_nonce(skData.abKey, CRYPT_KEY_SIZE_BYTES);
                if(fWriteToFile(fd, &skData, sizeof(skData)))
                {
                    ++nRecords;
                    printf("Record %d added successfully\n", nRecords);
                }
                break;
            
            case 2: break;
            default: logwarn("Invalid option!\n"); break;
        }
    }// while(1)
    
    loginfo("Total records written = %d\n", nRecords);
    fend:
    if(fd != -1) close(fd);
    return;
}


void vSplitUPFile()
{
    
}


void vSplitSKFile()
{
    
}

