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

#define FTYPE_UP    1   // user/passwd file
#define FTYPE_SK    2   // shared key file

// functions
BOOL fWriteToFile(int fd, void *pvData, int dataSize);
BOOL fReadLineFromStdin(char *pszBuffer, int nBufLen);
void vDisplayRecords(int fd, int ftype);

void vUserPasswdFile();
void vSharedKeyFile();
void vSplitUPFile();
void vSplitSKFile();

/*
 * 
 */
int main() {
    int userOption = -1;

    if (!fInitGCrypt())
        return 1;

    while (userOption != 7) 
    {
        printf("\nMenu\n1. Username/password file\n2. Shared key file\n");
        printf("3. Split username/password file\n4. Split shared key file\n");
        printf("5. Display username/password file\n6. Display shared key file\n");
        printf("7. Quit\n? ");
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
                break;
            
            case 4:
                break;
            
            case 5:
            case 6:
            {
                int fd = -1;
                int flags = O_RDONLY;
                char szFilepath[MAX_PATH+1];
                
                printf("Enter filename: ");
                fReadLineFromStdin(szFilepath, MAX_PATH+1);
                if((fd = iOpenFile(szFilepath, flags)) == -1)
                { logerr("open() "); break; }
                if(userOption == 5)
                    vDisplayRecords(fd, FTYPE_UP);
                else
                    vDisplayRecords(fd, FTYPE_SK);
                close(fd);
                fd = -1;
                break;
            }
            
            case 7:
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

/**
 * 
 * @param pszBuffer
 * @param nBufLen Includes the terminating NULL character
 * @return 
 */
BOOL fReadLineFromStdin(char *pszBuffer, int nBufLen) 
{
    ASSERT(pszBuffer && nBufLen > 0);

    int nlen = 0;
    char ch;

    if ((ch = getchar()) != '\n')
        ungetc(ch, stdin);

    while (nlen < nBufLen && (ch = getchar()) != '\n')
        pszBuffer[nlen++] = ch;
    pszBuffer[nlen] = 0;
    return TRUE;
}


void vDisplayRecords(int fd, int ftype)
{
    ssize_t uBytesRead = 0;

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
            printf("Key     : ");
            vPrintBytes(upData.abDerivedKey, CRYPT_KEY_SIZE_BYTES);
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
    
    while(1)
    {
        if((fd = open(pszFilepath, flags, openPerm)) == -1)
        {
            if(errno == ENOENT)
            {
                printf("File does not exist. Will create a new one...\n");
                flags = O_WRONLY | O_CREAT | O_TRUNC;
            }
            else
                break;
        }
        else
            break;
    }
    
    return fd;
}


void vUserPasswdFile()
{
    char szFile[MAX_PATH+1];
    char szPassphrase[MAX_PASSWD+1];
    
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
                if(fWriteToFile(fd, &upData, sizeof(upData)))
                {
                    ++nRecords;
                    printf("Record %d added successfully\n", nRecords);
                }
                break;
                
            case 3: break;
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

